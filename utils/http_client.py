"""
AGI-idor HTTP Client — Thread-safe rotating session manager with rate limiting,
proxy support, retry logic, and request logging.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Optional

import requests
from colorama import Fore, Style, init as colorama_init
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

colorama_init(autoreset=True)

logger = logging.getLogger("agi-idor.http")


class TokenBucketRateLimiter:
    """Thread-safe token bucket rate limiter."""

    def __init__(self, rate: float):
        self.rate = rate  # tokens per second
        self.tokens = rate
        self.max_tokens = rate
        self.lock = threading.Lock()
        self.last_refill = time.monotonic()

    def acquire(self) -> None:
        while True:
            with self.lock:
                now = time.monotonic()
                elapsed = now - self.last_refill
                self.tokens = min(self.max_tokens, self.tokens + elapsed * self.rate)
                self.last_refill = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
            time.sleep(0.05)


class RotatingHTTPClient:
    """HTTP client with session rotation, rate limiting, proxy support, and retry."""

    def __init__(
        self,
        proxy: Optional[str] = None,
        rate_limit: int = 10,
        timeout: int = 30,
        log_dir: str = "output/logs",
        user_agent: str = "AGI-idor/1.0",
        custom_headers: Optional[dict] = None,
    ):
        self.proxy = proxy
        self.timeout = timeout
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.user_agent = user_agent
        self.custom_headers = custom_headers or {}
        self.rate_limiter = TokenBucketRateLimiter(rate_limit)
        self._response_cache: dict[str, requests.Response] = {}
        self._cache_lock = threading.Lock()
        self._request_count = 0
        self._lock = threading.Lock()

        self.session = self._build_session()
        self._log_file = self.log_dir / "requests.jsonl"

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=20, pool_maxsize=20)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        session.headers["User-Agent"] = self.user_agent
        for k, v in self.custom_headers.items():
            session.headers[k] = v
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
            session.verify = False
        return session

    def switch_session(self, account_config: dict) -> None:
        """Switch HTTP session to use a different account's credentials."""
        self.session.headers.pop("Authorization", None)
        self.session.headers.pop("X-CSRF-Token", None)
        self.session.cookies.clear()

        headers = account_config.get("headers", {})
        for k, v in headers.items():
            self.session.headers[k] = v

        cookies = account_config.get("cookies", {})
        for k, v in cookies.items():
            self.session.cookies.set(k, v)

        if account_config.get("csrf_token"):
            self.session.headers["X-CSRF-Token"] = account_config["csrf_token"]

        acct_id = account_config.get("account_id", "unknown")
        print(f"{Fore.CYAN}[SESSION] Switched to account: {acct_id} (role: {account_config.get('role', 'unknown')}){Style.RESET_ALL}")

    def request(
        self,
        method: str,
        url: str,
        cache: bool = False,
        **kwargs: Any,
    ) -> requests.Response:
        """Send an HTTP request with rate limiting, caching, and logging."""
        self.rate_limiter.acquire()

        if cache:
            cache_key = self._cache_key(method, url, kwargs)
            with self._cache_lock:
                if cache_key in self._response_cache:
                    return self._response_cache[cache_key]

        kwargs.setdefault("timeout", self.timeout)

        with self._lock:
            self._request_count += 1
            req_num = self._request_count

        log_entry = {
            "request_number": req_num,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "method": method.upper(),
            "url": url,
            "headers": dict(self.session.headers),
        }
        if "json" in kwargs:
            log_entry["body"] = kwargs["json"]
        elif "data" in kwargs:
            log_entry["body"] = str(kwargs["data"])[:500]

        try:
            response = self.session.request(method, url, **kwargs)
            log_entry["status_code"] = response.status_code
            log_entry["response_size"] = len(response.content)

            status_color = Fore.GREEN if response.status_code < 400 else Fore.RED
            if response.status_code == 403:
                status_color = Fore.YELLOW
            print(
                f"{Fore.WHITE}[{req_num:04d}] {method.upper():6s} {url} "
                f"{status_color}{response.status_code}{Style.RESET_ALL} "
                f"({len(response.content)} bytes)"
            )

            if cache:
                with self._cache_lock:
                    self._response_cache[cache_key] = response

        except requests.RequestException as exc:
            log_entry["error"] = str(exc)
            print(f"{Fore.RED}[{req_num:04d}] {method.upper():6s} {url} ERROR: {exc}{Style.RESET_ALL}")
            raise
        finally:
            self._write_log(log_entry)

        return response

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("DELETE", url, **kwargs)

    def generate_curl(self, method: str, url: str, headers: Optional[dict] = None, body: Any = None) -> str:
        """Generate a curl command for evidence/reproduction."""
        parts = [f"curl -X {method.upper()}"]
        all_headers = {**dict(self.session.headers), **(headers or {})}
        for k, v in all_headers.items():
            if k.lower() not in ("user-agent", "accept-encoding", "connection"):
                parts.append(f"-H '{k}: {v}'")
        if body:
            if isinstance(body, dict):
                parts.append(f"-d '{json.dumps(body)}'")
            else:
                parts.append(f"-d '{body}'")
        parts.append(f"'{url}'")
        return " \\\n  ".join(parts)

    def _cache_key(self, method: str, url: str, kwargs: dict) -> str:
        raw = f"{method}:{url}:{json.dumps(kwargs.get('json', ''), sort_keys=True)}"
        return hashlib.md5(raw.encode()).hexdigest()

    def _write_log(self, entry: dict) -> None:
        try:
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except OSError:
            pass

    @property
    def total_requests(self) -> int:
        with self._lock:
            return self._request_count

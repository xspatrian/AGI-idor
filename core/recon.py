"""
AGI-idor Recon — JS bundle mining, endpoint extraction, API doc parsing,
GraphQL introspection, and priority scoring based on hunt-idor.md.
"""
from __future__ import annotations
import json, logging, re
from pathlib import Path
from typing import Any, Optional
from utils.http_client import RotatingHTTPClient
from utils.id_harvester import IDHarvester

logger = logging.getLogger("agi-idor.recon")

API_ROUTE_RE = re.compile(r'["\'](/?(?:api|graphql|v\d+|internal_api|admin)[^"\s\'{}]*)["\']')
GQL_OP_RE = re.compile(r'(?:operationName|operation_name)["\']?\s*[:=]\s*["\']([^"\']+)["\']')
GQL_DEF_RE = re.compile(r'(?:mutation|query)\s+(\w+)\s*(?:\(([^)]*)\))?')
ID_PARAM_RE = re.compile(r'\b(user_id|account_id|org_id|order_id|team_id|project_id|member_id|invoice_id|ticket_id|id|uuid|uid)\b', re.I)

PRIORITY_MAP = {
    "financial": 10, "admin": 9, "user_resource": 8, "export": 7,
    "messaging": 6, "file_download": 6, "graphql": 8, "internal": 9, "generic": 5,
}

INTROSPECTION_QUERY = """
{ __schema {
    queryType { fields { name description args { name type { name kind ofType { name kind } } } } }
    mutationType { fields { name description args { name type { name kind ofType { name kind } } } } }
    types { name kind fields { name args { name type { name kind ofType { name kind } } } } }
} }
"""

class IDORRecon:
    def __init__(self, target_config: dict, http_client: RotatingHTTPClient):
        self.config = target_config
        self.http = http_client
        self.harvester = IDHarvester(target_config.get("identifier_patterns", []))
        self.endpoints: list[dict] = []
        self.graphql_schema: Optional[dict] = None

    def discover_js_endpoints(self) -> list[dict]:
        """Download JS files and extract API routes, GraphQL ops, ID params."""
        results = []
        for js_url in self.config.get("js_files", []):
            logger.info(f"Fetching JS: {js_url}")
            try:
                resp = self.http.get(js_url, cache=True)
                if resp.status_code != 200:
                    continue
                content = resp.text
                for m in API_ROUTE_RE.finditer(content):
                    route = m.group(1)
                    if not route.startswith("/"): route = "/" + route
                    params = ID_PARAM_RE.findall(content[max(0,m.start()-200):m.end()+200])
                    ep = {"path": route, "method": "GET", "params": list(set(params)),
                          "source": "js_file", "js_url": js_url}
                    ep["category"] = self.classify_endpoint(route, "GET", ep["params"])
                    ep["priority"] = self.calculate_priority(ep)
                    results.append(ep)
                for m in GQL_OP_RE.finditer(content):
                    results.append({"path": "/graphql", "method": "POST",
                        "operation_name": m.group(1), "params": [],
                        "source": "js_file", "js_url": js_url,
                        "category": "graphql", "priority": PRIORITY_MAP["graphql"]})
                for m in GQL_DEF_RE.finditer(content):
                    args_str = m.group(2) or ""
                    params = re.findall(r'\$(\w+)', args_str)
                    id_params = [p for p in params if any(k in p.lower() for k in ("id","uuid","uid"))]
                    results.append({"path": "/graphql", "method": "POST",
                        "operation_name": m.group(1), "params": id_params,
                        "source": "js_file", "js_url": js_url,
                        "category": "graphql", "priority": PRIORITY_MAP["graphql"] + (2 if id_params else 0)})
                self.harvester.extract_from_js(content, js_url)
            except Exception as e:
                logger.error(f"Failed to fetch {js_url}: {e}")
        self.endpoints.extend(results)
        return results

    def discover_api_docs(self) -> list[dict]:
        """Fetch Swagger/OpenAPI specs and parse endpoints."""
        results = []
        for doc_url in self.config.get("api_docs", []):
            logger.info(f"Fetching API doc: {doc_url}")
            try:
                if "graphql" in doc_url.lower():
                    gql_results = self.discover_graphql_operations(doc_url)
                    results.extend(gql_results)
                    continue
                resp = self.http.get(doc_url, cache=True)
                if resp.status_code != 200: continue
                spec = resp.json()
                paths = spec.get("paths", {})
                for path, methods in paths.items():
                    for method, details in methods.items():
                        if method.lower() in ("get","post","put","patch","delete"):
                            params = []
                            for p in details.get("parameters", []):
                                pname = p.get("name", "")
                                if ID_PARAM_RE.search(pname) or pname.lower().endswith("id"):
                                    params.append(pname)
                            ep = {"path": path, "method": method.upper(), "params": params,
                                  "source": "api_doc", "doc_url": doc_url,
                                  "summary": details.get("summary", "")}
                            ep["category"] = self.classify_endpoint(path, method, params)
                            ep["priority"] = self.calculate_priority(ep)
                            results.append(ep)
            except Exception as e:
                logger.error(f"Failed to parse {doc_url}: {e}")
        self.endpoints.extend(results)
        return results

    def discover_graphql_operations(self, graphql_url: str = "") -> list[dict]:
        """Run GraphQL introspection and extract all ID-accepting operations."""
        url = graphql_url or f"{self.config['base_url']}/graphql"
        results = []
        try:
            resp = self.http.post(url, json={"query": INTROSPECTION_QUERY})
            if resp.status_code != 200:
                logger.warning(f"GraphQL introspection failed: {resp.status_code}")
                return results
            schema = resp.json()
            self.graphql_schema = schema
            data = schema.get("data", {}).get("__schema", {})
            for type_key in ("queryType", "mutationType"):
                type_data = data.get(type_key, {})
                if not type_data: continue
                for field in type_data.get("fields", []):
                    id_args = []
                    for arg in field.get("args", []):
                        arg_type = arg.get("type", {})
                        type_name = arg_type.get("name", "") or ""
                        inner = arg_type.get("ofType", {})
                        inner_name = inner.get("name", "") if inner else ""
                        if any(t in (type_name + inner_name).upper() for t in ("ID", "INT")):
                            id_args.append(arg["name"])
                        elif ID_PARAM_RE.search(arg["name"]):
                            id_args.append(arg["name"])
                    if id_args:
                        op_type = "mutation" if type_key == "mutationType" else "query"
                        results.append({
                            "path": url, "method": "POST",
                            "operation_name": field["name"],
                            "operation_type": op_type,
                            "id_args": id_args,
                            "all_args": [a["name"] for a in field.get("args", [])],
                            "params": id_args, "source": "graphql_introspection",
                            "category": "graphql",
                            "priority": PRIORITY_MAP["graphql"] + (3 if op_type == "mutation" else 1),
                        })
        except Exception as e:
            logger.error(f"GraphQL introspection failed: {e}")
        return results

    @staticmethod
    def classify_endpoint(path: str, method: str, params: list) -> str:
        p = path.lower()
        if any(k in p for k in ("/payment","/billing","/invoice","/order","/checkout","/subscription","/refund")):
            return "financial"
        if any(k in p for k in ("/admin","/manage","/internal","/mod","/dashboard")):
            return "admin"
        if any(k in p for k in ("/user","/profile","/account","/setting","/session","/password")):
            return "user_resource"
        if any(k in p for k in ("/export","/download","/report","/csv","/pdf","/backup")):
            return "export"
        if any(k in p for k in ("/message","/chat","/notification","/ticket","/support","/email")):
            return "messaging"
        if any(k in p for k in ("/file","/upload","/attachment","/media","/image")):
            return "file_download"
        if "graphql" in p:
            return "graphql"
        if "internal_api" in p:
            return "internal"
        return "generic"

    @staticmethod
    def calculate_priority(endpoint: dict) -> int:
        base = PRIORITY_MAP.get(endpoint.get("category", "generic"), 5)
        if endpoint.get("params"):
            base += len(endpoint["params"])
        if endpoint.get("method", "").upper() in ("PUT", "PATCH", "DELETE"):
            base += 2
        return min(base, 15)

    def get_sorted_endpoints(self) -> list[dict]:
        seen = set()
        unique = []
        for ep in self.endpoints:
            key = f"{ep['method']}:{ep['path']}:{ep.get('operation_name','')}"
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        return sorted(unique, key=lambda e: e.get("priority", 0), reverse=True)

    def save_results(self, output_dir: str = "output"):
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        eps = self.get_sorted_endpoints()
        with open(f"{output_dir}/discovered_endpoints.json", "w") as f:
            json.dump(eps, f, indent=2)
        if self.graphql_schema:
            with open(f"{output_dir}/graphql_schema.json", "w") as f:
                json.dump(self.graphql_schema, f, indent=2)
        self.harvester.save_to_file(f"{output_dir}/harvested_ids.json")
        logger.info(f"Saved {len(eps)} endpoints to {output_dir}/")

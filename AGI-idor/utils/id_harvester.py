"""
AGI-idor ID Harvester — Extract, classify, and track object identifiers
from HTTP responses, JS files, URLs, and cross-reference across accounts.
"""
from __future__ import annotations
import json, logging, re
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger("agi-idor.harvester")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
HASH_RE = re.compile(r"\b[0-9a-f]{24,64}\b", re.I)
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
API_ROUTE_RE = re.compile(r'["\']/((?:api|graphql|v\d+|internal_api)[^"\s\']*)["\']')
ID_PARAM_RE = re.compile(r"\b(user_id|account_id|org_id|order_id|team_id|project_id|member_id|invoice_id|ticket_id|id|uuid|uid)\b", re.I)

class HarvestedID:
    __slots__ = ("value","id_type","source","endpoint","field_name","account_id")
    def __init__(self, value, id_type, source, endpoint="", field_name="", account_id=""):
        self.value, self.id_type, self.source = value, id_type, source
        self.endpoint, self.field_name, self.account_id = endpoint, field_name, account_id
    def to_dict(self):
        return {s: getattr(self, s) for s in self.__slots__}

class IDHarvester:
    def __init__(self, patterns: Optional[list[str]] = None):
        self.custom_patterns = patterns or []
        self.harvested: list[HarvestedID] = []

    def extract_from_response(self, response: Any, account_id: str = "") -> list[HarvestedID]:
        results: list[HarvestedID] = []
        endpoint = str(getattr(response, "url", ""))
        results.extend(self.extract_from_url(endpoint, account_id))
        for hdr, val in getattr(response, "headers", {}).items():
            if any(k in hdr.lower() for k in ("id","user","account","tenant")):
                ct = self.classify_id(val)
                if ct != "unknown":
                    results.append(HarvestedID(val, ct, "header", endpoint, hdr, account_id))
        try:
            body = response.json()
            results.extend(self._from_json(body, endpoint, account_id))
        except (ValueError, AttributeError):
            text = getattr(response, "text", "")
            for m in UUID_RE.finditer(text):
                results.append(HarvestedID(m.group(), "uuid", "text_body", endpoint, "", account_id))
        self.harvested.extend(results)
        return results

    def extract_from_js(self, js_content: str, source_url: str = "") -> list[HarvestedID]:
        results: list[HarvestedID] = []
        for m in API_ROUTE_RE.finditer(js_content):
            results.append(HarvestedID("/"+m.group(1), "api_route", "js_file", source_url, "route"))
        for m in UUID_RE.finditer(js_content):
            results.append(HarvestedID(m.group(), "uuid", "js_file", source_url, "hardcoded"))
        for m in ID_PARAM_RE.finditer(js_content):
            results.append(HarvestedID(m.group(), "param_name", "js_file", source_url, "id_param"))
        for m in re.finditer(r'operationName["\']?\s*[:=]\s*["\']([^"\']+)["\']', js_content):
            results.append(HarvestedID(m.group(1), "graphql_op", "js_file", source_url, "op_name"))
        for m in re.finditer(r'(?:mutation|query)\s+(\w+)', js_content):
            results.append(HarvestedID(m.group(1), "graphql_op", "js_file", source_url, "op_def"))
        self.harvested.extend(results)
        return results

    def extract_from_url(self, url: str, account_id: str = "") -> list[HarvestedID]:
        results: list[HarvestedID] = []
        parsed = urlparse(url)
        segs = [s for s in parsed.path.split("/") if s]
        for i, seg in enumerate(segs):
            ct = self.classify_id(seg)
            if ct in ("sequential_int","uuid","hash"):
                ctx = segs[i-1] if i > 0 else "root"
                results.append(HarvestedID(seg, ct, "url_path", url, ctx, account_id))
        for pname, pvals in parse_qs(parsed.query).items():
            for v in pvals:
                ct = self.classify_id(v)
                if ct != "unknown":
                    results.append(HarvestedID(v, ct, "url_query", url, pname, account_id))
        return results

    @staticmethod
    def classify_id(value: str) -> str:
        v = value.strip()
        if not v: return "unknown"
        if UUID_RE.fullmatch(v): return "uuid"
        if v.isdigit() and 1 <= len(v) <= 10: return "sequential_int"
        if EMAIL_RE.fullmatch(v): return "email"
        if HASH_RE.fullmatch(v) and len(v) >= 24: return "hash"
        return "unknown"

    def cross_reference(self, ids_a: list[HarvestedID], ids_b: list[HarvestedID]) -> list[dict]:
        va = {h.value for h in ids_a}; vb = {h.value for h in ids_b}
        shared = va & vb
        return [{"value": v, "idor_potential": "HIGH",
                 "a": next((h.to_dict() for h in ids_a if h.value == v), None),
                 "b": next((h.to_dict() for h in ids_b if h.value == v), None)} for v in shared]

    def _from_json(self, data, endpoint, account_id, path="") -> list[HarvestedID]:
        results = []
        if isinstance(data, dict):
            for k, v in data.items():
                cp = f"{path}.{k}" if path else k
                if isinstance(v, (str,int,float)) and (ID_PARAM_RE.search(k) or k.lower().endswith("id")):
                    ct = self.classify_id(str(v))
                    results.append(HarvestedID(str(v), ct if ct!="unknown" else "field_value", "json_body", endpoint, cp, account_id))
                elif isinstance(v, (dict, list)):
                    results.extend(self._from_json(v, endpoint, account_id, cp))
        elif isinstance(data, list):
            for i, item in enumerate(data[:50]):
                results.extend(self._from_json(item, endpoint, account_id, f"{path}[{i}]"))
        return results

    def get_unique_ids(self, id_type: Optional[str] = None) -> list[str]:
        seen = set(); out = []
        for h in self.harvested:
            if id_type and h.id_type != id_type: continue
            if h.value not in seen: seen.add(h.value); out.append(h.value)
        return out

    def save_to_file(self, filepath: str):
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump([h.to_dict() for h in self.harvested], f, indent=2)

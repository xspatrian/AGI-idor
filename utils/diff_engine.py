"""
AGI-idor Diff Engine — Compare HTTP responses across accounts to detect
unauthorized data access, structural differences, and IDOR confirmation.
"""
from __future__ import annotations
import json, re, logging
from difflib import SequenceMatcher
from typing import Any, Optional

logger = logging.getLogger("agi-idor.diff")

DYNAMIC_FIELDS = re.compile(
    r"(csrf|nonce|timestamp|request_id|trace_id|x-request-id|date|expires|"
    r"set-cookie|etag|age|x-runtime|x-correlation)",
    re.I,
)

class DiffEngine:
    def __init__(self):
        self.diffs: list[dict] = []

    def compare(self, res_a: Any, res_b: Any) -> dict:
        """Compare two HTTP responses comprehensively."""
        result = {
            "status_a": getattr(res_a, "status_code", 0),
            "status_b": getattr(res_b, "status_code", 0),
            "size_a": len(getattr(res_a, "content", b"")),
            "size_b": len(getattr(res_b, "content", b"")),
            "status_match": False,
            "body_similarity": 0.0,
            "unique_fields_in_b": {},
            "classification": "unknown",
        }
        result["status_match"] = result["status_a"] == result["status_b"]

        body_a = getattr(res_a, "text", "")
        body_b = getattr(res_b, "text", "")
        result["body_similarity"] = self.similarity_score(body_a, body_b)

        try:
            json_a = res_a.json() if hasattr(res_a, "json") else {}
            json_b = res_b.json() if hasattr(res_b, "json") else {}
            result["unique_fields_in_b"] = self.extract_unique_fields(json_a, json_b)
        except (ValueError, AttributeError):
            pass

        result["classification"] = self.classify_diff(result)
        self.diffs.append(result)
        return result

    def similarity_score(self, body_a: str, body_b: str) -> float:
        """Calculate similarity score (0.0-1.0), ignoring dynamic tokens."""
        clean_a = DYNAMIC_FIELDS.sub("__DYNAMIC__", body_a)
        clean_b = DYNAMIC_FIELDS.sub("__DYNAMIC__", body_b)
        if not clean_a and not clean_b:
            return 1.0
        if not clean_a or not clean_b:
            return 0.0
        return SequenceMatcher(None, clean_a[:5000], clean_b[:5000]).ratio()

    def classify_diff(self, diff_result: dict) -> str:
        """Classify the difference into actionable categories."""
        sa, sb = diff_result["status_a"], diff_result["status_b"]
        sim = diff_result["body_similarity"]

        if sb == 401:
            return "auth_error"
        if sb == 403:
            return "auth_error"
        if sb == 404:
            return "not_found"
        if sb == 429:
            return "rate_limited"
        if sa == sb == 200:
            if sim > 0.95:
                return "identical"
            if sim > 0.7:
                return "structural"
            if diff_result.get("unique_fields_in_b"):
                return "data_leak"
            return "structural"
        if sa == 200 and sb == 200:
            return "data_leak" if diff_result.get("unique_fields_in_b") else "structural"
        return "unknown"

    def extract_unique_fields(self, json_a: Any, json_b: Any, path: str = "") -> dict:
        """Find fields in json_b that are not in json_a (unauthorized data)."""
        unique = {}
        if isinstance(json_b, dict):
            for key in json_b:
                cp = f"{path}.{key}" if path else key
                if key not in (json_a if isinstance(json_a, dict) else {}):
                    unique[cp] = json_b[key]
                elif isinstance(json_b[key], dict) and isinstance(json_a.get(key), dict):
                    nested = self.extract_unique_fields(json_a[key], json_b[key], cp)
                    unique.update(nested)
        return unique

    def is_idor_confirmed(self, baseline_response: Any, idor_response: Any) -> dict:
        """
        Compare baseline (own data) vs IDOR attempt (other's data).
        Returns confirmation verdict with evidence.
        """
        diff = self.compare(baseline_response, idor_response)
        confirmed = False
        confidence = "LOW"
        reason = ""

        idor_status = diff["status_b"]
        if idor_status == 200 and diff["body_similarity"] > 0.5:
            if diff["body_similarity"] < 0.95:
                confirmed = True
                confidence = "HIGH"
                reason = "200 OK with different data (similarity {:.0%})".format(diff["body_similarity"])
            else:
                confirmed = True
                confidence = "MEDIUM"
                reason = "200 OK with near-identical structure (may be same user's data reflection)"
        elif idor_status == 200 and diff["unique_fields_in_b"]:
            confirmed = True
            confidence = "HIGH"
            reason = f"200 OK with unique fields: {list(diff['unique_fields_in_b'].keys())[:5]}"
        elif idor_status in (403, 401):
            confirmed = False
            reason = f"Access denied ({idor_status})"
        elif idor_status == 404:
            confirmed = False
            reason = "Object not found"

        return {
            "confirmed": confirmed,
            "confidence": confidence,
            "reason": reason,
            "diff": diff,
        }

    def generate_diff_report(self) -> str:
        """Generate markdown report of all diffs."""
        lines = ["# Response Diff Report\n"]
        for i, d in enumerate(self.diffs, 1):
            lines.append(f"## Diff #{i}")
            lines.append(f"- **Status:** {d['status_a']} → {d['status_b']}")
            lines.append(f"- **Size:** {d['size_a']} → {d['size_b']} bytes")
            lines.append(f"- **Similarity:** {d['body_similarity']:.1%}")
            lines.append(f"- **Classification:** `{d['classification']}`")
            if d.get("unique_fields_in_b"):
                lines.append(f"- **Unique fields:** {list(d['unique_fields_in_b'].keys())[:10]}")
            lines.append("")
        return "\n".join(lines)

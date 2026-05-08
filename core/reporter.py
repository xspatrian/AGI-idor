"""
AGI-idor Reporter — Generates markdown findings per bug,
plus a consolidated final report with statistics.
"""
from __future__ import annotations
import json, time
from pathlib import Path
from typing import Any

class IDORReporter:
    def __init__(self, output_dir: str = "output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "findings").mkdir(exist_ok=True)
        (self.output_dir / "evidence").mkdir(exist_ok=True)
        self.findings: list[dict] = []

    def add_finding(self, finding: dict):
        self.findings.append(finding)

    def add_findings(self, findings: list[dict]):
        self.findings.extend(findings)

    def generate_finding_markdown(self, finding: dict, index: int = 0) -> str:
        vuln_type = finding.get("type", "Unknown IDOR")
        endpoint = finding.get("endpoint", "unknown")
        method = finding.get("method", "GET")
        severity = finding.get("severity", "Medium")
        confidence = finding.get("confidence", "MEDIUM")
        reason = finding.get("reason", "")
        test_id = finding.get("test_id", "")
        param = finding.get("param", "")
        curl = finding.get("curl_command", "")
        status = finding.get("status_code", 0)
        lines = [
            f"# Finding #{index}: {vuln_type} on {endpoint}\n",
            f"**Severity:** {severity}",
            f"**Confidence:** {confidence}",
            f"**Endpoint:** `{method} {endpoint}`",
            f"**Vulnerability Class:** {vuln_type}",
            f"**Timestamp:** {finding.get('timestamp', time.strftime('%Y-%m-%dT%H:%M:%S'))}\n",
            "## Description\n",
            f"{vuln_type} vulnerability detected on `{method} {endpoint}`.",
        ]
        if param and test_id:
            lines.append(f"The parameter `{param}` was set to `{test_id}` which returned "
                         f"HTTP {status}, indicating unauthorized access to another user's data.")
        if reason:
            lines.append(f"\n**Detection reason:** {reason}")
        lines.extend([
            "\n## Steps to Reproduce\n",
            f"1. Authenticate as the attacker account",
            f"2. Send the following request with the manipulated identifier:",
        ])
        if curl:
            lines.extend(["\n```bash", curl, "```\n"])
        lines.extend([
            f"3. Observe that the server returns HTTP {status} with data belonging to another user\n",
            "## Impact\n",
        ])
        if "Vertical" in vuln_type or "BAC" in vuln_type:
            lines.append("A low-privileged user can access administrative functionality, "
                         "potentially leading to privilege escalation and full application compromise.")
        elif "Cross-Tenant" in vuln_type:
            lines.append("An attacker can access data belonging to other organizations/tenants, "
                         "breaking multi-tenant isolation and potentially exposing all customers' data.")
        elif "GraphQL" in vuln_type:
            lines.append("The GraphQL API does not validate object ownership on this operation, "
                         "allowing any authenticated user to access or modify other users' data.")
        else:
            lines.append("An attacker can access or modify data belonging to other users "
                         "at the same privilege level (horizontal privilege escalation).")
        if finding.get("mass_impact_score"):
            score = finding["mass_impact_score"]
            lines.append(f"\n**Mass Impact Score:** {score:.1%} of tested IDs were accessible, "
                         f"indicating this vulnerability is {'mass-exploitable' if score > 0.5 else 'limited in scope'}.")
        lines.extend(["\n## Remediation\n",
            "- Implement server-side ownership validation on all object references",
            "- Verify that the authenticated user owns/has permission for the requested resource",
            "- Use indirect object references or access control lists",
            "- Add authorization middleware at the API gateway/framework level",
        ])
        return "\n".join(lines)

    def generate_report(self) -> str:
        """Generate consolidated markdown report."""
        lines = [
            "# AGI-idor Scan Report\n",
            f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Total Findings:** {len(self.findings)}\n",
            "---\n",
            "## Executive Summary\n",
        ]
        severity_counts = {}
        type_counts = {}
        for f in self.findings:
            s = f.get("severity", "Medium")
            t = f.get("type", "Unknown")
            severity_counts[s] = severity_counts.get(s, 0) + 1
            type_counts[t] = type_counts.get(t, 0) + 1
        lines.append("### Findings by Severity\n")
        lines.append("| Severity | Count |")
        lines.append("|---|---|")
        for s in ["Critical", "High", "Medium", "Low"]:
            if s in severity_counts:
                lines.append(f"| {s} | {severity_counts[s]} |")
        lines.append("\n### Findings by Type\n")
        lines.append("| Vulnerability Type | Count |")
        lines.append("|---|---|")
        for t, c in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"| {t} | {c} |")
        lines.append("\n---\n")
        lines.append("## Detailed Findings\n")
        for i, finding in enumerate(self.findings, 1):
            lines.append(self.generate_finding_markdown(finding, i))
            lines.append("\n---\n")
        return "\n".join(lines)

    def save_report(self):
        """Save individual findings and consolidated report."""
        for i, f in enumerate(self.findings, 1):
            md = self.generate_finding_markdown(f, i)
            filepath = self.output_dir / "findings" / f"finding_{i:03d}.md"
            filepath.write_text(md, encoding="utf-8")
        report = self.generate_report()
        report_path = self.output_dir / "report.md"
        report_path.write_text(report, encoding="utf-8")
        findings_json = self.output_dir / "all_findings.json"
        with open(findings_json, "w") as f:
            json.dump(self.findings, f, indent=2, default=str)
        print(f"\n[REPORT] Saved {len(self.findings)} findings to {self.output_dir}/")
        print(f"[REPORT] Consolidated report: {report_path}")
        return str(report_path)

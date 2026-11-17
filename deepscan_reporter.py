# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""
Deep scan report generator.

Generates reports from published findings:
- Per-finding reports with evidence, CWE, CVSS, permalink
- Summary rollup by severity and verdict
- Merged output combining fast-path and deep-path results
- JSON export for machine consumption

Only published (true-positive) findings appear in the final report.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from finding_store import FindingStore, FindingState, Verdict

logger = logging.getLogger(__name__)


class DeepScanReporter:
    """
    Deep scan report generator.

    Generates Markdown and JSON reports from the finding store.
    Only published (true-positive) findings are surfaced.
    """

    def __init__(self, finding_store: FindingStore,
                 output_dir: str = "security-reports",
                 repo_url: Optional[str] = None,
                 commit_sha: Optional[str] = None):
        self.store = finding_store
        self.output_dir = output_dir
        self.repo_url = repo_url
        self.commit_sha = commit_sha
        os.makedirs(output_dir, exist_ok=True)

    def generate_report(self, show_needs_review: bool = False) -> str:
        """
        Generate the full deep scan report.

        Returns the path to the generated Markdown report.
        """
        published = self.store.get_findings(state=FindingState.PUBLISHED)
        needs_review = self.store.get_findings(verdict=Verdict.NEEDS_REVIEW) if show_needs_review else []
        summary = self.store.export_summary()

        report = self._build_markdown(published, needs_review, summary)

        report_path = os.path.join(self.output_dir, "deepscan_report.md")
        with open(report_path, "w") as f:
            f.write(report)

        logger.info("Deep scan report written to %s", report_path)
        return report_path

    def generate_json_report(self) -> str:
        """Generate a machine-readable JSON report of published findings."""
        published = self.store.get_findings(state=FindingState.PUBLISHED)
        summary = self.store.export_summary()

        data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "findings": published,
        }

        report_path = os.path.join(self.output_dir, "deepscan_report.json")
        with open(report_path, "w") as f:
            json.dump(data, f, indent=2, default=str)

        logger.info("Deep scan JSON report written to %s", report_path)
        return report_path

    def _build_markdown(self, published: List[Dict[str, Any]],
                        needs_review: List[Dict[str, Any]],
                        summary: Dict[str, Any]) -> str:
        """Build the Markdown report content."""
        lines: List[str] = []

        # Header
        lines.append("# AI Deep SAST — Security Report")
        lines.append("")
        lines.append(f"**Generated**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        if self.commit_sha:
            lines.append(f"**Commit**: `{self.commit_sha[:12]}`")
        lines.append(f"**Model**: Opus 4 (Anthropic)")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append("")
        finding_counts = summary.get("findings", {})
        lines.append(f"| Metric | Count |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Total findings analysed | {finding_counts.get('total', 0)} |")
        lines.append(f"| True positives (published) | {len(published)} |")

        fp_count = finding_counts.get("verdict:false-positive", 0)
        nr_count = finding_counts.get("verdict:needs-review", 0)
        lines.append(f"| False positives | {fp_count} |")
        lines.append(f"| Needs review | {nr_count} |")

        lines.append(f"| Rule gaps recorded | {summary.get('rule_gaps', 0)} |")
        lines.append("")

        # Severity breakdown
        if published:
            severity_counts = {"ERROR": 0, "WARNING": 0, "INFO": 0}
            for f in published:
                tier = f.get("severity_tier", "INFO")
                severity_counts[tier] = severity_counts.get(tier, 0) + 1

            lines.append("### Severity Breakdown")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            for tier in ("ERROR", "WARNING", "INFO"):
                if severity_counts[tier] > 0:
                    lines.append(f"| {tier} | {severity_counts[tier]} |")
            lines.append("")

        # Published findings
        lines.append("---")
        lines.append("")

        if published:
            lines.append("## Confirmed Vulnerabilities")
            lines.append("")
            for i, finding in enumerate(published, 1):
                lines.extend(self._format_finding(i, finding))
                lines.append("")
        else:
            lines.append("## Confirmed Vulnerabilities")
            lines.append("")
            lines.append("No confirmed vulnerabilities found by the deep-path analysis.")
            lines.append("")

        # Needs review (optional)
        if needs_review:
            lines.append("---")
            lines.append("")
            lines.append("## Needs Review")
            lines.append("")
            lines.append("*These findings could not be fully confirmed or denied.*")
            lines.append("")
            for i, finding in enumerate(needs_review, 1):
                lines.extend(self._format_finding(i, finding, is_review=True))
                lines.append("")

        # Footer
        lines.append("---")
        lines.append("")
        lines.append("*Report generated by AI Deep SAST (deep scan)*")

        return "\n".join(lines)

    def _format_finding(self, index: int, finding: Dict[str, Any],
                        is_review: bool = False) -> List[str]:
        """Format a single finding for the Markdown report."""
        lines: List[str] = []

        vuln_class = finding.get("vulnerability_class", "Unknown")
        severity = finding.get("severity_tier", "INFO")
        cvss = finding.get("severity_cvss")

        prefix = "NR" if is_review else "F"
        lines.append(f"### {prefix}-{index}: {vuln_class}")
        lines.append("")

        # Metadata table
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| **Severity** | {severity}" + (f" (CVSS {cvss:.1f})" if cvss else "") + " |")
        lines.append(f"| **CWE** | {finding.get('cwe', 'N/A')} |")
        lines.append(f"| **File** | `{finding.get('file_path', 'N/A')}` |")
        lines.append(f"| **Function** | `{finding.get('function_name', 'N/A')}` |")
        lines.append(f"| **Detection** | {finding.get('detection_technique', 'N/A')} |")

        # Permalink
        permalink = self._build_permalink(finding)
        if permalink:
            lines.append(f"| **Link** | [{finding.get('file_path', '')}]({permalink}) |")

        lines.append("")

        # Description
        desc = finding.get("description", "")
        if desc:
            lines.append(f"**Description**: {desc}")
            lines.append("")

        # Evidence report
        evidence = finding.get("evidence_report", "")
        if evidence:
            lines.append(f"**Evidence**: {evidence}")
            lines.append("")

        return lines

    def _build_permalink(self, finding: Dict[str, Any]) -> Optional[str]:
        """Build a commit-pinned permalink (FR-084)."""
        if not self.repo_url or not self.commit_sha:
            return None

        file_path = finding.get("file_path", "")
        if not file_path:
            return None

        # Normalise to relative path
        if file_path.startswith("/"):
            # Try to make relative — this is best-effort
            file_path = file_path.split("/")[-1] if "/" in file_path else file_path

        return f"{self.repo_url}/blob/{self.commit_sha}/{file_path}"

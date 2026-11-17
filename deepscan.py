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
AI Deep SAST — deep scan CLI entry point.

Performs LLM-powered deep static analysis by extracting every function
from the codebase and analysing it with a frontier model.

Usage:
    python3 deepscan.py --target ./src
    python3 deepscan.py --target ./src --show-needs-review
    python3 deepscan.py --target ./src --dry-run   # index only, no LLM calls

Configure your LLM provider via environment variables:
    export LLM_BASE_URL=https://api.openai.com/v1
    export LLM_API_KEY=sk-proj-abc123...
    export LLM_MODEL=gpt-4o
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

from asvs_loader import ASVSLoader
from codeguard_loader import CodeGuardLoader
from detector import Detector
from finding_store import FindingStore
from deepscan_reporter import DeepScanReporter
from indexer import CodeIndex
from llm_client import LLMClient
from rule_matcher import RuleMatcher
from triager import Triager

logger = logging.getLogger("deepscan")


class Orchestrator:
    """
    Deep scan orchestrator.

    Manages the analysis pipeline:
    1. Pre-flight checks
    2. Code indexing (tree-sitter, 15 languages)
    3. LLM-powered detection (rule-based + exploratory)
    4. Evidence-gated triage
    5. Report generation
    """

    def __init__(self, target: str, output_dir: str = "security-reports",
                 db_path: Optional[str] = None,
                 show_needs_review: bool = False,
                 repo_url: Optional[str] = None,
                 commit_sha: Optional[str] = None,
                 dry_run: bool = False,
                 guided: bool = False,
                 guide_rules: str = "both",
                 skip_exploratory: bool = False,
                 llm_url: Optional[str] = None,
                 llm_api_key: Optional[str] = None,
                 llm_model: Optional[str] = None):
        self.target = os.path.abspath(target)
        self.output_dir = output_dir
        self.db_path = db_path or os.path.join(output_dir, "deepscan.db")
        self.llm_url = llm_url
        self.llm_api_key = llm_api_key
        self.llm_model = llm_model
        self.show_needs_review = show_needs_review
        self.repo_url = repo_url
        self.commit_sha = commit_sha or self._get_git_commit()
        self.dry_run = dry_run
        self.guided = guided
        self.guide_rules = guide_rules
        self.skip_exploratory = skip_exploratory

        # Components (initialised in run())
        self.store: Optional[FindingStore] = None
        self.index: Optional[CodeIndex] = None
        self.llm: Optional[LLMClient] = None
        self.detector: Optional[Detector] = None
        self.triager: Optional[Triager] = None
        self.reporter: Optional[DeepScanReporter] = None

    def run(self) -> Dict[str, Any]:
        """
        Run the full deep scan pipeline.

        Returns a summary dict with stats from each phase.
        """
        # Determine scan mode label
        if self.guided:
            mode_label = {"asvs": "ASVS-guided", "codeguard": "CodeGuard-guided",
                          "both": "ASVS+CodeGuard-guided", "semgrep": "Semgrep-guided"}[self.guide_rules]
        else:
            mode_label = "Brute-force"

        results: Dict[str, Any] = {
            "target": self.target,
            "scan_mode": mode_label,
            "phases": {},
            "success": False,
        }
        start_time = time.time()

        try:
            # Phase 0: Pre-flight
            logger.info("=" * 60)
            logger.info("AI DEEP SAST — Mode: %s", mode_label)
            logger.info("Target: %s", self.target)
            logger.info("=" * 60)

            if not self._preflight_check():
                results["error"] = "Pre-flight check failed"
                return results

            # Initialise components
            self._init_components()

            # Phase 1: Index
            logger.info("")
            logger.info("--- Phase 1: Indexing ---")
            index_stats = self._run_index()
            results["phases"]["index"] = index_stats
            logger.info("Indexed %d functions in %d files",
                        index_stats.get("functions_found", 0),
                        index_stats.get("files_parsed", 0))

            if not self.index.is_queryable:
                logger.warning("No functions found — nothing to scan")
                results["error"] = "No functions found in target"
                return results

            if self.dry_run:
                logger.info("")
                logger.info("--- DRY RUN — skipping LLM phases ---")
                results["phases"]["dry_run"] = True
                results["success"] = True
                self._save_index()
                return results

            # Phase 2: Detection
            logger.info("")
            logger.info("--- Phase 2: Detection ---")
            detect_stats = self._run_detection()
            results["phases"]["detection"] = detect_stats
            logger.info("Detection: %d candidates from rule-based, %d from exploratory",
                        detect_stats.get("rule_based", {}).get("candidates_created", 0),
                        detect_stats.get("exploratory", {}).get("candidates_created", 0))

            # Phase 3: Triage
            logger.info("")
            logger.info("--- Phase 3: Triage ---")
            triage_stats = self.triager.triage_all_candidates()
            results["phases"]["triage"] = triage_stats
            logger.info("Triage: TP:%d FP:%d NR:%d",
                        triage_stats.get("true_positive", 0),
                        triage_stats.get("false_positive", 0),
                        triage_stats.get("needs_review", 0))

            # Phase 4: Reports
            logger.info("")
            logger.info("--- Phase 4: Reports ---")
            report_path = self.reporter.generate_report(
                show_needs_review=self.show_needs_review
            )
            json_path = self.reporter.generate_json_report()
            results["phases"]["reports"] = {
                "markdown": report_path,
                "json": json_path,
            }
            logger.info("Reports: %s", report_path)

            # Save index for incremental re-use
            self._save_index()

            # Summary
            results["success"] = True
            results["token_usage"] = self.llm.usage.to_dict()

        except Exception as e:
            logger.error("Deep scan failed: %s", e, exc_info=True)
            results["error"] = str(e)

        finally:
            elapsed = time.time() - start_time
            results["elapsed_seconds"] = round(elapsed, 2)
            self._print_summary(results)

        return results

    def _preflight_check(self) -> bool:
        """Pre-flight checks."""
        ok = True

        # Check target exists
        if not os.path.exists(self.target):
            logger.error("Target does not exist: %s", self.target)
            ok = False

        # Check API key (skip for dry-run)
        if not self.dry_run:
            test_client = self._build_llm_client()
            if not test_client.is_available():
                logger.error(
                    "LLM API key not found. Set LLM_API_KEY environment variable.\n"
                    "  Example: export LLM_API_KEY=sk-proj-abc123..."
                )
                ok = False
            else:
                logger.info("API key: configured")

        logger.info("Target: %s (%s)", self.target,
                     "directory" if os.path.isdir(self.target) else "file")
        return ok

    def _init_components(self):
        """Initialise all agent components."""
        self.store = FindingStore(db_path=self.db_path)
        self.index = CodeIndex()

        if not self.dry_run:
            self.llm = self._build_llm_client()

        self.reporter = DeepScanReporter(
            self.store, output_dir=self.output_dir,
            repo_url=self.repo_url, commit_sha=self.commit_sha,
        )

    def _run_index(self) -> Dict[str, Any]:
        """Run the Indexer phase."""
        # Try to load existing index for incremental
        index_path = os.path.join(self.output_dir, "deepscan_index.json")
        if os.path.exists(index_path):
            self.index.load(index_path)
            logger.info("Loaded existing index from %s", index_path)

        return self.index.build(self.target)

    def _save_index(self):
        """Save the index for incremental re-use."""
        index_path = os.path.join(self.output_dir, "deepscan_index.json")
        self.index.save(index_path)

    def _run_detection(self) -> Dict[str, Any]:
        """Run detection techniques based on mode."""
        rule_matcher = None
        if self.guided and self.guide_rules != "semgrep":
            rule_matcher = self._init_rule_matcher()

        self.detector = Detector(self.llm, self.index, self.store,
                                 rule_matcher=rule_matcher)
        self.triager = Triager(self.llm, self.index, self.store)

        stats: Dict[str, Any] = {}

        if self.guided and self.guide_rules == "semgrep":
            # Semgrep-guided: Opus validates Semgrep findings
            logger.info("Running SEMGREP-GUIDED detection...")
            semgrep_results = self._run_semgrep()
            stats["semgrep_guided"] = self.detector.run_semgrep_guided(semgrep_results)
        elif self.guided and rule_matcher:
            # ASVS/CodeGuard guided mode: only matched functions go to Opus
            label = {"asvs": "ASVS only", "codeguard": "CodeGuard only", "both": "ASVS + CodeGuard"}[self.guide_rules]
            logger.info("Running GUIDED detection (%s)...", label)
            stats["guided"] = self.detector.run_guided()
        else:
            # Brute-force: every function to Opus
            logger.info("Running rule-based detection...")
            stats["rule_based"] = self.detector.run_rule_based()

            # Exploratory (free-form hunting)
            if self.skip_exploratory:
                logger.info("Skipping exploratory detection (--skip-exploratory)")
                stats["exploratory"] = {"skipped": True}
            else:
                logger.info("Running exploratory detection...")
                stats["exploratory"] = self.detector.run_exploratory()

        return stats

    def _run_semgrep(self) -> List[Dict[str, Any]]:
        """Run Semgrep scan and return results list."""
        semgrep_output = os.path.join(self.output_dir, "semgrep_report.json")

        # Check for existing Semgrep results first
        if os.path.exists(semgrep_output):
            logger.info("Loading existing Semgrep results from %s", semgrep_output)
            with open(semgrep_output) as f:
                data = json.load(f)
            results = data.get("results", [])
            logger.info("Semgrep: %d findings loaded", len(results))
            return results

        # Run Semgrep
        logger.info("Running Semgrep scan on %s...", self.target)
        cmd = ["semgrep", "--config", "p/default", "--config", "p/secrets",
               "--json", f"--output={semgrep_output}", "--metrics=off",
               self.target]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            if result.returncode > 1:
                logger.error("Semgrep failed: %s", result.stderr[:500])
                return []
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.error("Semgrep error: %s", e)
            return []

        with open(semgrep_output) as f:
            data = json.load(f)
        results = data.get("results", [])
        logger.info("Semgrep: %d findings from scan", len(results))
        return results

    def _init_rule_matcher(self) -> Optional[RuleMatcher]:
        """Initialise ASVS + CodeGuard loaders and rule matcher."""
        asvs = None
        codeguard = None
        asvs_count = 0
        cg_count = 0

        if self.guide_rules in ("asvs", "both"):
            asvs = ASVSLoader()
            asvs_count = asvs.load()
            logger.info("ASVS: %d requirements loaded", asvs_count)

        if self.guide_rules in ("codeguard", "both"):
            codeguard = CodeGuardLoader()
            cg_count = codeguard.load()
            logger.info("CodeGuard: %d rules loaded", cg_count)

        if asvs_count == 0 and cg_count == 0:
            logger.warning("No ASVS or CodeGuard rules loaded — falling back to brute-force")
            return None

        return RuleMatcher(asvs=asvs, codeguard=codeguard)

    def _print_summary(self, results: Dict[str, Any]):
        """Print a summary to the console."""
        logger.info("")
        logger.info("=" * 60)
        logger.info("DEEP SCAN COMPLETE")
        logger.info("=" * 60)

        if results.get("error"):
            logger.error("Error: %s", results["error"])
            return

        phases = results.get("phases", {})

        # Index
        idx = phases.get("index", {})
        logger.info("Files indexed: %d (%d functions)",
                     idx.get("files_parsed", 0), idx.get("functions_found", 0))

        if phases.get("dry_run"):
            logger.info("Mode: DRY RUN (no LLM calls)")
            return

        # Detection
        det = phases.get("detection", {})
        if "semgrep_guided" in det:
            sg = det["semgrep_guided"]
            logger.info("Semgrep → Opus: %d findings validated, %d TP (%.1f%%), %d FP, %d candidates",
                         sg.get("findings_validated", 0),
                         sg.get("confirmed_tp", 0),
                         (sg.get("confirmed_tp", 0) /
                          max(sg.get("confirmed_tp", 0) + sg.get("confirmed_fp", 0), 1) * 100),
                         sg.get("confirmed_fp", 0),
                         sg.get("candidates_created", 0))
        elif "guided" in det:
            gd = det["guided"]
            logger.info("Guided: %d functions, %d matched, %d skipped (%.1f%% filtered), %d candidates",
                         gd.get("total_functions", 0),
                         gd.get("functions_analysed", 0),
                         gd.get("rule_skipped", 0),
                         (gd.get("rule_skipped", 0) / max(gd.get("total_functions", 1), 1) * 100),
                         gd.get("candidates_created", 0))
        else:
            rb = det.get("rule_based", {})
            ex = det.get("exploratory", {})
            logger.info("Candidates: %d rule-based + %d exploratory = %d total",
                         rb.get("candidates_created", 0),
                         ex.get("candidates_created", 0),
                         rb.get("candidates_created", 0) + ex.get("candidates_created", 0))

        # Triage
        tri = phases.get("triage", {})
        logger.info("Verdicts: %d TP, %d FP, %d NR",
                     tri.get("true_positive", 0),
                     tri.get("false_positive", 0),
                     tri.get("needs_review", 0))

        # Cost
        usage = results.get("token_usage", {})
        if usage:
            logger.info("Tokens: %d in + %d out ($%.4f est.)",
                        usage.get("total_input_tokens", 0),
                        usage.get("total_output_tokens", 0),
                        usage.get("estimated_cost_usd", 0))

        # Reports
        reports = phases.get("reports", {})
        if reports:
            logger.info("Report: %s", reports.get("markdown", ""))

        logger.info("Time: %.1fs", results.get("elapsed_seconds", 0))

    def _build_llm_client(self) -> LLMClient:
        """Build an LLMClient with CLI overrides or env var defaults."""
        kwargs = {}
        if self.llm_url:
            kwargs["base_url"] = self.llm_url
        if self.llm_api_key:
            kwargs["api_key"] = self.llm_api_key
        if self.llm_model:
            kwargs["model"] = self.llm_model
        return LLMClient(**kwargs)

    @staticmethod
    def _get_git_commit() -> Optional[str]:
        """Try to get the current git commit SHA."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None


def main():
    parser = argparse.ArgumentParser(
        description="AI Deep SAST — deep scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python3 deepscan.py --target ./src
  python3 deepscan.py --target ./src --dry-run
  python3 deepscan.py --target ./src --show-needs-review
  python3 deepscan.py --target ./src --output-dir reports/
        """,
    )
    parser.add_argument("--target", required=True,
                        help="File or directory to scan")
    parser.add_argument("--output-dir", default="security-reports",
                        help="Directory for reports and data (default: security-reports)")
    parser.add_argument("--db-path", default=None,
                        help="Path to SQLite database (default: <output-dir>/deepscan.db)")
    parser.add_argument("--llm-url", default=None,
                        help="LLM API base URL (default: env LLM_BASE_URL or https://api.openai.com/v1)")
    parser.add_argument("--llm-api-key", default=None,
                        help="LLM API key (default: env LLM_API_KEY)")
    parser.add_argument("--llm-model", default=None,
                        help="LLM model name (default: env LLM_MODEL or gpt-4o)")
    parser.add_argument("--show-needs-review", action="store_true",
                        help="Include needs-review findings in the report")
    parser.add_argument("--repo-url", default=None,
                        help="Repository URL for commit-pinned permalinks")
    parser.add_argument("--commit", default=None,
                        help="Commit SHA for permalinks (auto-detected from git)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Index only — no LLM calls (for testing)")
    parser.add_argument("--guided", action="store_true",
                        help="Use rule-guided scanning (faster, targeted)")
    parser.add_argument("--skip-exploratory", action="store_true",
                        help="Skip exploratory detection (use for mode comparison runs)")
    parser.add_argument("--guide-rules", default="both",
                        choices=["asvs", "codeguard", "both", "semgrep"],
                        help="Which rules to use in guided mode: asvs, codeguard, both, or semgrep (default: both)")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Logging level (default: INFO)")
    parser.add_argument("--json-summary", action="store_true",
                        help="Print JSON summary to stdout on completion")

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    orchestrator = Orchestrator(
        target=args.target,
        output_dir=args.output_dir,
        db_path=args.db_path,
        show_needs_review=args.show_needs_review,
        repo_url=args.repo_url,
        commit_sha=args.commit,
        dry_run=args.dry_run,
        guided=args.guided,
        guide_rules=args.guide_rules,
        skip_exploratory=args.skip_exploratory,
        llm_url=args.llm_url,
        llm_api_key=args.llm_api_key,
        llm_model=args.llm_model,
    )

    results = orchestrator.run()

    if args.json_summary:
        print(json.dumps(results, indent=2, default=str))

    sys.exit(0 if results.get("success") else 1)


if __name__ == "__main__":
    main()

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

"""Tests for the deep scan Orchestrator and standalone CLI."""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from deepscan import Orchestrator


PYTHON_SAMPLE = '''\
def handle_login(username, password):
    query = f"SELECT * FROM users WHERE name='{username}'"
    return db.execute(query)

def safe_function():
    return "hello"
'''

JAVA_SAMPLE = '''\
public class App {
    public void processInput(String input) {
        System.out.println(input);
    }
}
'''


@pytest.fixture
def scan_dir(tmp_path):
    """Create a directory with sample files to scan."""
    (tmp_path / "app.py").write_text(PYTHON_SAMPLE)
    (tmp_path / "App.java").write_text(JAVA_SAMPLE)
    return str(tmp_path)


@pytest.fixture
def output_dir(tmp_path):
    d = str(tmp_path / "reports")
    os.makedirs(d, exist_ok=True)
    return d


# --- Dry run (no LLM) ---

class TestDryRun:
    """Tests for dry-run mode (index only, no LLM calls)."""

    def test_dry_run_succeeds(self, scan_dir, output_dir):
        orch = Orchestrator(
            target=scan_dir,
            output_dir=output_dir,
            dry_run=True,
        )
        results = orch.run()
        assert results["success"] is True
        assert results["phases"].get("dry_run") is True

    def test_dry_run_indexes_files(self, scan_dir, output_dir):
        orch = Orchestrator(target=scan_dir, output_dir=output_dir, dry_run=True)
        results = orch.run()
        idx = results["phases"]["index"]
        assert idx["files_parsed"] == 2
        assert idx["functions_found"] >= 3  # handle_login, safe_function, processInput

    def test_dry_run_saves_index(self, scan_dir, output_dir):
        orch = Orchestrator(target=scan_dir, output_dir=output_dir, dry_run=True)
        orch.run()
        assert os.path.exists(os.path.join(output_dir, "deepscan_index.json"))

    def test_dry_run_no_api_key_required(self, scan_dir, output_dir, monkeypatch):
        monkeypatch.delenv("LLM_API_KEY", raising=False)
        orch = Orchestrator(
            target=scan_dir, output_dir=output_dir,
            dry_run=True,
        )
        results = orch.run()
        assert results["success"] is True

    def test_dry_run_single_file(self, tmp_path, output_dir):
        f = tmp_path / "single.py"
        f.write_text("def foo(): pass\ndef bar(): pass\n")
        orch = Orchestrator(target=str(f), output_dir=output_dir, dry_run=True)
        results = orch.run()
        assert results["success"] is True
        assert results["phases"]["index"]["functions_found"] == 2

    def test_dry_run_empty_directory(self, tmp_path, output_dir):
        empty = tmp_path / "empty"
        empty.mkdir()
        orch = Orchestrator(target=str(empty), output_dir=output_dir, dry_run=True)
        results = orch.run()
        assert results["success"] is False
        assert "No functions found" in results.get("error", "")


# --- Pre-flight checks ---

class TestPreflight:
    """Tests for pre-flight validation."""

    def test_nonexistent_target(self, output_dir):
        orch = Orchestrator(target="/nonexistent/path", output_dir=output_dir, dry_run=True)
        results = orch.run()
        assert results["success"] is False

    def test_preflight_checks_api_key(self, scan_dir, output_dir, monkeypatch):
        monkeypatch.delenv("LLM_API_KEY", raising=False)
        orch = Orchestrator(
            target=scan_dir, output_dir=output_dir,
            dry_run=False,
        )
        results = orch.run()
        assert results["success"] is False
        assert "Pre-flight" in results.get("error", "")


# --- Full pipeline (mocked LLM) ---

class TestFullPipeline:
    """Tests for the full pipeline with mocked LLM."""

    def test_full_pipeline_with_mock(self, scan_dir, output_dir, monkeypatch):
        monkeypatch.setenv("LLM_API_KEY", "test-key")

        # Mock the LLM client's chat method
        mock_response = json.dumps([{
            "vulnerability_class": "sql-injection",
            "description": "SQL injection via f-string",
            "cwe": "CWE-89",
            "severity_tier": "ERROR",
            "severity_cvss": 8.5,
        }])
        mock_triage_response = json.dumps({
            "verdict": "true-positive",
            "confidence": 0.95,
            "evidence_report": "Confirmed SQL injection. User input in f-string query.",
        })

        with patch("deepscan.LLMClient") as MockLLM:
            mock_instance = MagicMock()
            mock_instance.is_available.return_value = True
            mock_instance.usage = MagicMock()
            mock_instance.usage.to_dict.return_value = {
                "total_input_tokens": 500,
                "total_output_tokens": 200,
                "total_calls": 5,
                "estimated_cost_usd": 0.0225,
            }
            # Alternate between detector and triager responses
            mock_instance.chat.side_effect = [
                (mock_response, {"input_tokens": 100, "output_tokens": 50}),  # detect func 1
                (mock_response, {"input_tokens": 100, "output_tokens": 50}),  # detect func 2
                (mock_response, {"input_tokens": 100, "output_tokens": 50}),  # detect func 3
                ("[]", {"input_tokens": 50, "output_tokens": 5}),  # exploratory batch
                (mock_triage_response, {"input_tokens": 200, "output_tokens": 100}),  # triage 1
            ]
            MockLLM.return_value = mock_instance

            orch = Orchestrator(
                target=scan_dir,
                output_dir=output_dir,
                repo_url="https://github.com/test/repo",
                commit_sha="abc123",
            )
            results = orch.run()

        assert results["success"] is True
        assert "detection" in results["phases"]
        assert "triage" in results["phases"]
        assert "reports" in results["phases"]

        # Check reports exist
        md_path = results["phases"]["reports"]["markdown"]
        json_path = results["phases"]["reports"]["json"]
        assert os.path.exists(md_path)
        assert os.path.exists(json_path)


# --- Incremental indexing ---

class TestIncremental:
    """Tests for incremental re-indexing."""

    def test_incremental_reuses_index(self, scan_dir, output_dir):
        # First run
        orch1 = Orchestrator(target=scan_dir, output_dir=output_dir, dry_run=True)
        r1 = orch1.run()
        assert r1["phases"]["index"]["files_parsed"] == 2

        # Second run — should skip unchanged files
        orch2 = Orchestrator(target=scan_dir, output_dir=output_dir, dry_run=True)
        r2 = orch2.run()
        assert r2["phases"]["index"]["files_skipped"] == 2
        assert r2["phases"]["index"]["files_parsed"] == 0


# --- CLI args ---

class TestCLI:
    """Tests for CLI argument parsing."""

    def test_cli_help(self):
        """Verify the CLI module can be imported and main exists."""
        from deepscan import main
        assert callable(main)

    def test_orchestrator_defaults(self, scan_dir):
        orch = Orchestrator(target=scan_dir)
        assert orch.output_dir == "security-reports"
        assert orch.show_needs_review is False
        assert orch.dry_run is False

    def test_orchestrator_custom_args(self, scan_dir, output_dir):
        orch = Orchestrator(
            target=scan_dir,
            output_dir=output_dir,
            show_needs_review=True,
            repo_url="https://github.com/test",
            commit_sha="abc123",
            dry_run=True,
        )
        assert orch.show_needs_review is True
        assert orch.repo_url == "https://github.com/test"
        assert orch.commit_sha == "abc123"
        assert orch.dry_run is True


# --- JSON summary ---

class TestJsonSummary:
    """Tests for the JSON summary output."""

    def test_results_structure(self, scan_dir, output_dir):
        orch = Orchestrator(target=scan_dir, output_dir=output_dir, dry_run=True)
        results = orch.run()

        assert "target" in results
        assert "phases" in results
        assert "success" in results
        assert "elapsed_seconds" in results
        assert isinstance(results["elapsed_seconds"], float)

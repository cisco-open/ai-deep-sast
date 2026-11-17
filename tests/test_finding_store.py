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

"""Tests for the finding store and work queue."""

import json
import os
import tempfile

import pytest

from finding_store import (
    FindingState,
    FindingStore,
    TaskState,
    Verdict,
    compute_fingerprint,
)


@pytest.fixture
def store(tmp_path):
    """Create a FindingStore with a temporary database."""
    db_path = str(tmp_path / "test_deepscan.db")
    return FindingStore(db_path=db_path)


# --- Fingerprinting (FR-090) ---

class TestFingerprint:
    """Tests for finding fingerprint computation."""

    def test_fingerprint_deterministic(self):
        fp1 = compute_fingerprint("src/app.py", "handle_login", "sql-injection")
        fp2 = compute_fingerprint("src/app.py", "handle_login", "sql-injection")
        assert fp1 == fp2

    def test_fingerprint_different_files(self):
        fp1 = compute_fingerprint("src/app.py", "handle_login", "sql-injection")
        fp2 = compute_fingerprint("src/auth.py", "handle_login", "sql-injection")
        assert fp1 != fp2

    def test_fingerprint_different_functions(self):
        fp1 = compute_fingerprint("src/app.py", "handle_login", "sql-injection")
        fp2 = compute_fingerprint("src/app.py", "handle_logout", "sql-injection")
        assert fp1 != fp2

    def test_fingerprint_different_vuln_class(self):
        fp1 = compute_fingerprint("src/app.py", "handle_login", "sql-injection")
        fp2 = compute_fingerprint("src/app.py", "handle_login", "xss")
        assert fp1 != fp2

    def test_fingerprint_normalises_path(self):
        fp1 = compute_fingerprint("src/app.py", "func", "sqli")
        fp2 = compute_fingerprint("src/../src/app.py", "func", "sqli")
        assert fp1 == fp2

    def test_fingerprint_none_function(self):
        fp1 = compute_fingerprint("src/app.py", None, "hardcoded-secret")
        fp2 = compute_fingerprint("src/app.py", None, "hardcoded-secret")
        assert fp1 == fp2

    def test_fingerprint_length(self):
        fp = compute_fingerprint("src/app.py", "func", "sqli")
        assert len(fp) == 16


# --- Finding CRUD ---

class TestFindingCRUD:
    """Tests for finding create/read operations."""

    def test_add_finding(self, store):
        fid = store.add_finding(
            file_path="src/app.py",
            vulnerability_class="sql-injection",
            description="SQL injection via string concatenation",
            function_name="handle_login",
        )
        assert fid is not None

        finding = store.get_finding(fid)
        assert finding["file_path"] == "src/app.py"
        assert finding["vulnerability_class"] == "sql-injection"
        assert finding["state"] == FindingState.CANDIDATE.value
        assert finding["verdict"] is None

    def test_add_duplicate_returns_none(self, store):
        fid1 = store.add_finding(
            file_path="src/app.py",
            vulnerability_class="sql-injection",
            description="First",
            function_name="handle_login",
        )
        fid2 = store.add_finding(
            file_path="src/app.py",
            vulnerability_class="sql-injection",
            description="Duplicate",
            function_name="handle_login",
        )
        assert fid1 is not None
        assert fid2 is None

    def test_different_vuln_class_not_duplicate(self, store):
        fid1 = store.add_finding(
            file_path="src/app.py",
            vulnerability_class="sql-injection",
            description="SQLi",
            function_name="handle_login",
        )
        fid2 = store.add_finding(
            file_path="src/app.py",
            vulnerability_class="xss",
            description="XSS",
            function_name="handle_login",
        )
        assert fid1 is not None
        assert fid2 is not None

    def test_get_finding_not_found(self, store):
        assert store.get_finding("nonexistent") is None

    def test_get_finding_by_fingerprint(self, store):
        store.add_finding(
            file_path="src/app.py",
            vulnerability_class="sql-injection",
            description="SQLi",
            function_name="func",
        )
        fp = compute_fingerprint("src/app.py", "func", "sql-injection")
        finding = store.get_finding_by_fingerprint(fp)
        assert finding is not None
        assert finding["vulnerability_class"] == "sql-injection"

    def test_has_fingerprint(self, store):
        assert not store.has_fingerprint("src/app.py", "func", "sqli")
        store.add_finding(
            file_path="src/app.py",
            vulnerability_class="sqli",
            description="test",
            function_name="func",
        )
        assert store.has_fingerprint("src/app.py", "func", "sqli")

    def test_add_finding_with_metadata(self, store):
        fid = store.add_finding(
            file_path="src/app.py",
            vulnerability_class="sqli",
            description="test",
            severity_cvss=8.5,
            severity_tier="ERROR",
            cwe="CWE-89",
            metadata={"owasp": "A03:2021"},
        )
        finding = store.get_finding(fid)
        assert finding["severity_cvss"] == 8.5
        assert finding["severity_tier"] == "ERROR"
        assert finding["cwe"] == "CWE-89"
        meta = json.loads(finding["metadata"])
        assert meta["owasp"] == "A03:2021"


# --- Verdict lifecycle (§7) ---

class TestVerdictLifecycle:
    """Tests for finding lifecycle and verdicts."""

    def test_set_true_positive_with_evidence(self, store):
        fid = store.add_finding(
            file_path="src/app.py",
            vulnerability_class="sqli",
            description="test",
        )
        result = store.set_verdict(
            fid, Verdict.TRUE_POSITIVE,
            evidence_report="Reachable via /login endpoint, crosses trust boundary at line 42"
        )
        assert result is True
        finding = store.get_finding(fid)
        assert finding["verdict"] == Verdict.TRUE_POSITIVE.value
        assert finding["state"] == FindingState.CONFIRMED.value

    def test_true_positive_requires_evidence(self, store):
        fid = store.add_finding(
            file_path="src/app.py",
            vulnerability_class="sqli",
            description="test",
        )
        result = store.set_verdict(fid, Verdict.TRUE_POSITIVE)
        assert result is False
        finding = store.get_finding(fid)
        assert finding["verdict"] is None

    def test_set_false_positive(self, store):
        fid = store.add_finding(
            file_path="src/app.py",
            vulnerability_class="sqli",
            description="test",
        )
        result = store.set_verdict(fid, Verdict.FALSE_POSITIVE)
        assert result is True
        finding = store.get_finding(fid)
        assert finding["verdict"] == Verdict.FALSE_POSITIVE.value
        assert finding["state"] == FindingState.CANDIDATE.value

    def test_set_needs_review(self, store):
        fid = store.add_finding(
            file_path="src/app.py",
            vulnerability_class="sqli",
            description="test",
        )
        result = store.set_verdict(fid, Verdict.NEEDS_REVIEW)
        assert result is True
        finding = store.get_finding(fid)
        assert finding["verdict"] == Verdict.NEEDS_REVIEW.value

    def test_publish_confirmed_finding(self, store):
        fid = store.add_finding(
            file_path="src/app.py",
            vulnerability_class="sqli",
            description="test",
        )
        store.set_verdict(fid, Verdict.TRUE_POSITIVE, evidence_report="evidence")
        result = store.publish_finding(fid)
        assert result is True
        finding = store.get_finding(fid)
        assert finding["state"] == FindingState.PUBLISHED.value

    def test_cannot_publish_unconfirmed(self, store):
        fid = store.add_finding(
            file_path="src/app.py",
            vulnerability_class="sqli",
            description="test",
        )
        result = store.publish_finding(fid)
        assert result is False

    def test_cannot_publish_false_positive(self, store):
        fid = store.add_finding(
            file_path="src/app.py",
            vulnerability_class="sqli",
            description="test",
        )
        store.set_verdict(fid, Verdict.FALSE_POSITIVE)
        result = store.publish_finding(fid)
        assert result is False

    def test_set_verdict_nonexistent_finding(self, store):
        result = store.set_verdict("nonexistent", Verdict.FALSE_POSITIVE)
        assert result is False


# --- Finding queries ---

class TestFindingQueries:
    """Tests for finding query and count operations."""

    def test_get_findings_by_state(self, store):
        fid1 = store.add_finding("a.py", "sqli", "test1")
        fid2 = store.add_finding("b.py", "xss", "test2")
        store.set_verdict(fid1, Verdict.TRUE_POSITIVE, evidence_report="evidence")

        candidates = store.get_findings(state=FindingState.CANDIDATE)
        confirmed = store.get_findings(state=FindingState.CONFIRMED)
        assert len(candidates) == 1
        assert len(confirmed) == 1

    def test_get_findings_by_verdict(self, store):
        fid1 = store.add_finding("a.py", "sqli", "test1")
        fid2 = store.add_finding("b.py", "xss", "test2")
        store.set_verdict(fid1, Verdict.TRUE_POSITIVE, evidence_report="evidence")
        store.set_verdict(fid2, Verdict.FALSE_POSITIVE)

        tp = store.get_findings(verdict=Verdict.TRUE_POSITIVE)
        fp = store.get_findings(verdict=Verdict.FALSE_POSITIVE)
        assert len(tp) == 1
        assert len(fp) == 1

    def test_get_findings_count(self, store):
        store.add_finding("a.py", "sqli", "test1")
        store.add_finding("b.py", "xss", "test2")
        fid3 = store.add_finding("c.py", "ssrf", "test3")
        store.set_verdict(fid3, Verdict.FALSE_POSITIVE)

        counts = store.get_findings_count()
        assert counts["total"] == 3
        # false-positive stays in candidate state (only true-positive → confirmed)
        assert counts["state:candidate"] == 3
        assert counts["verdict:false-positive"] == 1


# --- Work queue (§8.1) ---

class TestWorkQueue:
    """Tests for the work queue with atomic claims."""

    def test_add_and_claim_task(self, store):
        tid = store.add_task("Investigate auth module", "Check for bypass", priority=5)
        task = store.claim_task("agent-1")
        assert task is not None
        assert task["id"] == tid
        assert task["claimed_by"] == "agent-1"

    def test_claim_returns_highest_priority(self, store):
        store.add_task("Low priority", priority=1)
        store.add_task("High priority", priority=10)
        store.add_task("Mid priority", priority=5)

        task = store.claim_task("agent-1")
        assert task["title"] == "High priority"

    def test_claim_atomic_no_double_claim(self, store):
        store.add_task("Single task", priority=1)
        task1 = store.claim_task("agent-1")
        task2 = store.claim_task("agent-2")
        assert task1 is not None
        assert task2 is None

    def test_release_task_reopens(self, store):
        tid = store.add_task("Reusable task")
        store.claim_task("agent-1")
        store.release_task(tid, "agent-1", completed=False)

        task = store.claim_task("agent-2")
        assert task is not None
        assert task["claimed_by"] == "agent-2"
        assert task["claim_count"] == 1

    def test_release_task_completed(self, store):
        tid = store.add_task("One-time task")
        store.claim_task("agent-1")
        store.release_task(tid, "agent-1", completed=True)

        tasks = store.get_tasks(TaskState.CLOSED)
        assert len(tasks) == 1
        assert tasks[0]["id"] == tid

    def test_auto_block_after_max_claims(self, store):
        tid = store.add_task("Problematic task")

        for i in range(3):
            store.claim_task(f"agent-{i}")
            store.release_task(tid, f"agent-{i}", completed=False)

        tasks = store.get_tasks(TaskState.BLOCKED)
        assert len(tasks) == 1
        assert tasks[0]["id"] == tid

    def test_claim_with_role_filter(self, store):
        store.add_task("Detector task", role="detector")
        store.add_task("Triager task", role="triager")

        task = store.claim_task("agent-1", role="triager")
        assert task is not None
        assert task["title"] == "Triager task"

    def test_release_wrong_agent(self, store):
        tid = store.add_task("Task")
        store.claim_task("agent-1")
        result = store.release_task(tid, "agent-2", completed=True)
        assert result is False

    def test_no_tasks_available(self, store):
        task = store.claim_task("agent-1")
        assert task is None


# --- Rule gaps (FR-042) ---

class TestRuleGaps:
    """Tests for rule gap recording."""

    def test_record_rule_gap(self, store):
        fid = store.add_finding("src/app.py", "logic-flaw", "Custom auth bypass")
        gap_id = store.record_rule_gap(
            fid, "auth-bypass",
            "Custom authentication logic skips validation when token is empty"
        )
        assert gap_id is not None

        gaps = store.get_rule_gaps()
        assert len(gaps) == 1
        assert gaps[0]["vulnerability_class"] == "auth-bypass"

    def test_record_multiple_gaps(self, store):
        fid1 = store.add_finding("a.py", "logic-flaw", "test1")
        fid2 = store.add_finding("b.py", "race-condition", "test2")
        store.record_rule_gap(fid1, "logic-flaw", "desc1")
        store.record_rule_gap(fid2, "race-condition", "desc2")

        gaps = store.get_rule_gaps()
        assert len(gaps) == 2

# --- Export ---

class TestExport:
    """Tests for data export."""

    def test_export_findings_json(self, store):
        store.add_finding("src/app.py", "sqli", "test")
        result = store.export_findings_json()
        data = json.loads(result)
        assert len(data) == 1
        assert data[0]["vulnerability_class"] == "sqli"

    def test_export_summary(self, store):
        store.add_finding("a.py", "sqli", "test1")
        store.add_task("Task 1")

        summary = store.export_summary()
        assert summary["findings"]["total"] == 1
        assert summary["tasks"]["open"] == 1
        assert summary["rule_gaps"] == 0

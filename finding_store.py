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
Finding store and work queue for deep scan.

SQLite-backed persistent store implementing the finding
lifecycle, fingerprinting, deduplication, and
work queue with atomic claims.

Constitution alignment:
  I.   Evidence Over Assertion — findings carry structured evidence
  II.  Surface Only What Survives — only true-positive reaches reports
  IV.  Claims Are Atomic And Mortal — SQLite atomic claim/release
  VIII. Fingerprints Stable Under Edit — hash(path + symbol + class)
  XI.  Persist Atomically — write-new-then-swap via SQLite transactions
"""

import hashlib
import json
import logging
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# --- Finding lifecycle enums (§7) ---

class FindingState(str, Enum):
    """Finding lifecycle states (§7.1)."""
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    PUBLISHED = "published"


class Verdict(str, Enum):
    """Triager verdicts (§7.2)."""
    TRUE_POSITIVE = "true-positive"
    FALSE_POSITIVE = "false-positive"
    NEEDS_REVIEW = "needs-review"
    NOT_APPLICABLE = "not-applicable"
    CODE_QUALITY = "code-quality"


class TaskState(str, Enum):
    """Work queue task states (FR-094)."""
    OPEN = "open"
    BLOCKED = "blocked"
    CLOSED = "closed"


# --- Schema ---

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    file_path TEXT NOT NULL,
    function_name TEXT,
    vulnerability_class TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'candidate',
    verdict TEXT,
    severity_cvss REAL,
    severity_tier TEXT,
    cwe TEXT,
    description TEXT,
    evidence_report TEXT,
    detection_technique TEXT,
    rule_id TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_state ON findings(state);
CREATE INDEX IF NOT EXISTS idx_findings_verdict ON findings(verdict);

CREATE TABLE IF NOT EXISTS work_queue (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    priority INTEGER DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'open',
    role TEXT,
    claimed_by TEXT,
    claimed_at TEXT,
    claim_count INTEGER DEFAULT 0,
    max_claims INTEGER DEFAULT 3,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_work_queue_state ON work_queue(state);
CREATE INDEX IF NOT EXISTS idx_work_queue_claimed_by ON work_queue(claimed_by);

CREATE TABLE IF NOT EXISTS rule_gaps (
    id TEXT PRIMARY KEY,
    finding_id TEXT REFERENCES findings(id),
    vulnerability_class TEXT NOT NULL,
    pattern_description TEXT,
    suggested_rule TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS processed_functions (
    fingerprint TEXT PRIMARY KEY,
    file_path TEXT NOT NULL,
    function_name TEXT,
    processed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_processed_file ON processed_functions(file_path);
"""


# --- Fingerprinting (FR-090) ---

def compute_fingerprint(file_path: str, function_name: Optional[str],
                        vulnerability_class: str) -> str:
    """
    Compute a stable finding fingerprint (FR-090).

    Hash of (normalised file path, function/symbol name, vulnerability class).
    No line numbers, code snippets, or timestamps — stable across edits.
    """
    normalised_path = os.path.normpath(file_path)
    parts = [
        normalised_path,
        function_name or "",
        vulnerability_class,
    ]
    content = "|".join(parts)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


# --- Store ---

class FindingStore:
    """
    SQLite-backed finding store and work queue.

    Thread-safe via SQLite's built-in locking. All writes are atomic
    within transactions (Constitution XI).
    """

    def __init__(self, db_path: str = "security-reports/deepscan.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Create tables if they don't exist."""
        with self._connect() as conn:
            conn.executescript(_SCHEMA_SQL)

    @contextmanager
    def _connect(self):
        """Context manager for database connections with WAL mode."""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _new_id() -> str:
        return uuid.uuid4().hex[:12]

    # --- Finding operations ---

    def add_finding(self, file_path: str, vulnerability_class: str,
                    description: str, detection_technique: str = "rule-based",
                    function_name: Optional[str] = None,
                    rule_id: Optional[str] = None,
                    severity_cvss: Optional[float] = None,
                    severity_tier: Optional[str] = None,
                    cwe: Optional[str] = None,
                    metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """
        Add a candidate finding. Returns finding ID, or None if duplicate (FR-045/FR-091).

        Deduplicates by fingerprint — if a finding with the same fingerprint
        exists, it is NOT added again.
        """
        fingerprint = compute_fingerprint(file_path, function_name, vulnerability_class)
        now = self._now()
        finding_id = self._new_id()

        with self._connect() as conn:
            try:
                conn.execute(
                    """INSERT INTO findings
                       (id, fingerprint, file_path, function_name, vulnerability_class,
                        state, description, detection_technique, rule_id,
                        severity_cvss, severity_tier, cwe, metadata,
                        created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (finding_id, fingerprint, file_path, function_name,
                     vulnerability_class, FindingState.CANDIDATE.value,
                     description, detection_technique, rule_id,
                     severity_cvss, severity_tier, cwe,
                     json.dumps(metadata) if metadata else None,
                     now, now)
                )
                logger.info("Finding added: %s (fingerprint: %s)", finding_id, fingerprint)
                return finding_id
            except sqlite3.IntegrityError:
                logger.debug("Duplicate finding skipped (fingerprint: %s)", fingerprint)
                return None

    def set_verdict(self, finding_id: str, verdict: Verdict,
                    evidence_report: Optional[str] = None) -> bool:
        """
        Assign a verdict to a finding (FR-050).

        A verdict without an evidence report is rejected for true-positive (FR-054).
        true-positive moves state to CONFIRMED.
        """
        if verdict == Verdict.TRUE_POSITIVE and not evidence_report:
            logger.error("Cannot set true-positive without evidence report (FR-054)")
            return False

        new_state = FindingState.CONFIRMED.value if verdict == Verdict.TRUE_POSITIVE \
            else FindingState.CANDIDATE.value
        now = self._now()

        with self._connect() as conn:
            cursor = conn.execute(
                """UPDATE findings
                   SET verdict = ?, evidence_report = ?, state = ?, updated_at = ?
                   WHERE id = ?""",
                (verdict.value, evidence_report, new_state, now, finding_id)
            )
            if cursor.rowcount == 0:
                logger.error("Finding not found: %s", finding_id)
                return False
            logger.info("Verdict set: %s → %s", finding_id, verdict.value)
            return True

    def publish_finding(self, finding_id: str) -> bool:
        """
        Mark a confirmed finding as published (FR-079).

        Only true-positive findings can be published.
        """
        now = self._now()
        with self._connect() as conn:
            cursor = conn.execute(
                """UPDATE findings SET state = ?, updated_at = ?
                   WHERE id = ? AND state = ? AND verdict = ?""",
                (FindingState.PUBLISHED.value, now, finding_id,
                 FindingState.CONFIRMED.value, Verdict.TRUE_POSITIVE.value)
            )
            if cursor.rowcount == 0:
                logger.error("Cannot publish finding %s: must be confirmed true-positive", finding_id)
                return False
            logger.info("Finding published: %s", finding_id)
            return True

    def get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Get a single finding by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
            return dict(row) if row else None

    def mark_function_processed(self, file_path: str, function_name: Optional[str]) -> None:
        """Record that a function has been analysed (for resume support)."""
        fp = compute_fingerprint(file_path, function_name, "__processed__")
        now = self._now()
        with self._connect() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO processed_functions
                   (fingerprint, file_path, function_name, processed_at)
                   VALUES (?, ?, ?, ?)""",
                (fp, file_path, function_name, now)
            )

    def is_function_processed(self, file_path: str, function_name: Optional[str]) -> bool:
        """Check if a function was already analysed (for resume support)."""
        fp = compute_fingerprint(file_path, function_name, "__processed__")
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM processed_functions WHERE fingerprint = ?", (fp,)
            ).fetchone()
            return row is not None

    def get_processed_count(self) -> int:
        """Return the number of functions already processed."""
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM processed_functions").fetchone()
            return row[0] if row else 0

    def mark_batch_processed(self, batch_key: str) -> None:
        """Record that an exploratory batch has been analysed (for resume support)."""
        fp = compute_fingerprint(batch_key, None, "__exploratory_batch__")
        now = self._now()
        with self._connect() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO processed_functions
                   (fingerprint, file_path, function_name, processed_at)
                   VALUES (?, ?, ?, ?)""",
                (fp, batch_key, "__exploratory_batch__", now)
            )

    def is_batch_processed(self, batch_key: str) -> bool:
        """Check if an exploratory batch was already analysed (for resume support)."""
        fp = compute_fingerprint(batch_key, None, "__exploratory_batch__")
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM processed_functions WHERE fingerprint = ?", (fp,)
            ).fetchone()
            return row is not None

    def get_finding_by_fingerprint(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        """Get a finding by its fingerprint."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
            return dict(row) if row else None

    def get_findings(self, state: Optional[FindingState] = None,
                     verdict: Optional[Verdict] = None) -> List[Dict[str, Any]]:
        """Query findings with optional state/verdict filters."""
        query = "SELECT * FROM findings WHERE 1=1"
        params: List[Any] = []

        if state:
            query += " AND state = ?"
            params.append(state.value)
        if verdict:
            query += " AND verdict = ?"
            params.append(verdict.value)

        query += " ORDER BY created_at DESC"

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def get_findings_count(self) -> Dict[str, int]:
        """Get finding counts by state and verdict."""
        with self._connect() as conn:
            counts: Dict[str, int] = {}
            for row in conn.execute(
                "SELECT state, COUNT(*) as cnt FROM findings GROUP BY state"
            ).fetchall():
                counts[f"state:{row['state']}"] = row["cnt"]
            for row in conn.execute(
                "SELECT verdict, COUNT(*) as cnt FROM findings WHERE verdict IS NOT NULL GROUP BY verdict"
            ).fetchall():
                counts[f"verdict:{row['verdict']}"] = row["cnt"]
            counts["total"] = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            return counts

    def has_fingerprint(self, file_path: str, function_name: Optional[str],
                        vulnerability_class: str) -> bool:
        """Check if a finding with this fingerprint already exists (FR-091)."""
        fp = compute_fingerprint(file_path, function_name, vulnerability_class)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM findings WHERE fingerprint = ?", (fp,)
            ).fetchone()
            return row is not None

    # --- Work queue operations (§8.1) ---

    def add_task(self, title: str, description: str = "",
                 priority: int = 0, role: Optional[str] = None) -> str:
        """Add a task to the work queue (FR-098)."""
        task_id = self._new_id()
        now = self._now()

        with self._connect() as conn:
            conn.execute(
                """INSERT INTO work_queue
                   (id, title, description, priority, state, role, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (task_id, title, description, priority,
                 TaskState.OPEN.value, role, now, now)
            )
        logger.info("Task added: %s — %s", task_id, title)
        return task_id

    def claim_task(self, agent_id: str,
                   role: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Atomically claim the highest-priority open task (FR-095).

        Returns the claimed task, or None if no tasks available.
        """
        now = self._now()
        with self._connect() as conn:
            role_filter = " AND role = ?" if role else ""
            params: List[Any] = [TaskState.OPEN.value]
            if role:
                params.append(role)

            row = conn.execute(
                f"""SELECT * FROM work_queue
                    WHERE state = ?{role_filter}
                    AND claimed_by IS NULL
                    ORDER BY priority DESC, created_at ASC
                    LIMIT 1""",
                params
            ).fetchone()

            if not row:
                return None

            task_id = row["id"]
            conn.execute(
                """UPDATE work_queue
                   SET claimed_by = ?, claimed_at = ?, updated_at = ?
                   WHERE id = ? AND claimed_by IS NULL""",
                (agent_id, now, now, task_id)
            )

            updated = conn.execute(
                "SELECT * FROM work_queue WHERE id = ?", (task_id,)
            ).fetchone()

            if updated and updated["claimed_by"] == agent_id:
                logger.info("Task %s claimed by %s", task_id, agent_id)
                return dict(updated)
            return None

    def release_task(self, task_id: str, agent_id: str,
                     completed: bool = False) -> bool:
        """
        Release a claimed task (FR-096).

        If completed, closes the task. Otherwise releases the claim
        and increments claim_count. Auto-blocks after max_claims (FR-097).
        """
        now = self._now()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM work_queue WHERE id = ? AND claimed_by = ?",
                (task_id, agent_id)
            ).fetchone()

            if not row:
                logger.error("Task %s not claimed by %s", task_id, agent_id)
                return False

            if completed:
                conn.execute(
                    """UPDATE work_queue
                       SET state = ?, claimed_by = NULL, claimed_at = NULL, updated_at = ?
                       WHERE id = ?""",
                    (TaskState.CLOSED.value, now, task_id)
                )
                logger.info("Task %s completed by %s", task_id, agent_id)
            else:
                new_count = row["claim_count"] + 1
                new_state = TaskState.BLOCKED.value if new_count >= row["max_claims"] \
                    else TaskState.OPEN.value

                conn.execute(
                    """UPDATE work_queue
                       SET claimed_by = NULL, claimed_at = NULL,
                           claim_count = ?, state = ?, updated_at = ?
                       WHERE id = ?""",
                    (new_count, new_state, now, task_id)
                )
                if new_state == TaskState.BLOCKED.value:
                    logger.warning("Task %s auto-blocked after %d claims (FR-097)",
                                   task_id, new_count)
                else:
                    logger.info("Task %s released by %s (claim %d/%d)",
                                task_id, agent_id, new_count, row["max_claims"])
            return True

    def get_tasks(self, state: Optional[TaskState] = None) -> List[Dict[str, Any]]:
        """Get tasks with optional state filter."""
        if state:
            query = "SELECT * FROM work_queue WHERE state = ? ORDER BY priority DESC, created_at ASC"
            params: Tuple = (state.value,)
        else:
            query = "SELECT * FROM work_queue ORDER BY priority DESC, created_at ASC"
            params = ()

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    # --- Rule gap operations (FR-042) ---

    def record_rule_gap(self, finding_id: str, vulnerability_class: str,
                        pattern_description: str,
                        suggested_rule: Optional[str] = None) -> str:
        """
        Record a rule gap (FR-042).

        When an exploratory finding is confirmed true-positive and no
        detection rule would have produced it, record the gap.
        """
        gap_id = self._new_id()
        now = self._now()

        with self._connect() as conn:
            conn.execute(
                """INSERT INTO rule_gaps
                   (id, finding_id, vulnerability_class, pattern_description,
                    suggested_rule, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (gap_id, finding_id, vulnerability_class,
                 pattern_description, suggested_rule, now)
            )
        logger.info("Rule gap recorded: %s (class: %s)", gap_id, vulnerability_class)
        return gap_id

    def get_rule_gaps(self) -> List[Dict[str, Any]]:
        """Get all recorded rule gaps."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM rule_gaps ORDER BY created_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    # --- Export ---

    def export_findings_json(self, state: Optional[FindingState] = None,
                             verdict: Optional[Verdict] = None) -> str:
        """Export findings as JSON string."""
        findings = self.get_findings(state=state, verdict=verdict)
        return json.dumps(findings, indent=2, default=str)

    def export_summary(self) -> Dict[str, Any]:
        """Export a summary of the store's state."""
        return {
            "findings": self.get_findings_count(),
            "tasks": {
                "open": len(self.get_tasks(TaskState.OPEN)),
                "blocked": len(self.get_tasks(TaskState.BLOCKED)),
                "closed": len(self.get_tasks(TaskState.CLOSED)),
            },
            "rule_gaps": len(self.get_rule_gaps()),
        }

"""
Advanced Aura Cognitive Memory Manager for SecAgent.
Integrates Aura Cognitive Memory Architecture (DNA layering, cognitive crystallization, decay & reinforcement)
with a zero-dependency local SQLite persistent storage fallback.
"""

from __future__ import annotations

import json
import hashlib
import logging
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from collections.abc import Iterator

logger = logging.getLogger(__name__)


@dataclass
class TargetDNA:
    """Target identity DNA fingerprint."""

    target: str
    domain: str
    tech_stack: List[str] = field(default_factory=list)
    waf_signature: Optional[str] = None
    rate_limit_detected: bool = False
    recommended_concurrency: int = 8
    last_scanned: float = field(default_factory=time.time)


@dataclass
class CognitivePattern:
    """Crystallized security pattern (e.g. successful payload, WAF bypass, auth trick)."""

    pattern_id: str
    target: str
    vuln_type: str
    payload: str
    waf_bypassed: bool
    confidence: float
    occurrences: int = 1
    last_verified: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


class AuraMemoryManager:
    """
    Cognitive Memory Manager for SecAgent Swarm.
    Supports aura-memory SDK interface with built-in SQLite persistence fallback.
    """

    _instance: Optional[AuraMemoryManager] = None

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or (Path.home() / ".secagents" / "cognitive_memory.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("secagents.aura_memory")
        self._sdk_available = False
        self._aura_sdk = None

        self._init_sdk_if_available()
        self._init_sqlite_schema()

    @classmethod
    def get_instance(cls) -> AuraMemoryManager:
        if cls._instance is None:
            cls._instance = AuraMemoryManager()
        return cls._instance

    def _init_sdk_if_available(self) -> None:
        """Attempt to load aura-memory SDK if installed."""
        try:
            import aura_memory  # type: ignore[import-not-found]

            self._aura_sdk = aura_memory.MemoryEngine()
            self._sdk_available = True
            self.logger.info("AuraMemoryManager: Loaded official aura-memory SDK engine")
        except ImportError:
            self.logger.info(
                "AuraMemoryManager: Operating in native embedded cognitive memory mode"
            )

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_sqlite_schema(self) -> None:
        """Initialize local SQLite persistence tables."""
        try:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS target_dna (
                        target TEXT PRIMARY KEY,
                        domain TEXT,
                        tech_stack TEXT,
                        waf_signature TEXT,
                        rate_limit_detected INTEGER,
                        recommended_concurrency INTEGER,
                        last_scanned REAL
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS cognitive_patterns (
                        pattern_id TEXT PRIMARY KEY,
                        target TEXT,
                        vuln_type TEXT,
                        payload TEXT,
                        waf_bypassed INTEGER,
                        confidence REAL,
                        occurrences INTEGER,
                        last_verified REAL,
                        metadata TEXT
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS fuzz_attempts (
                        target_key TEXT NOT NULL,
                        category TEXT NOT NULL,
                        fingerprint TEXT NOT NULL,
                        outcome TEXT NOT NULL,
                        attempted_at REAL NOT NULL,
                        PRIMARY KEY (target_key, category, fingerprint)
                    )
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS fuzz_attempts_age ON fuzz_attempts(attempted_at)
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS fuzz_operator_feedback (
                        target_key TEXT NOT NULL,
                        category TEXT NOT NULL,
                        operator TEXT NOT NULL,
                        attempts INTEGER NOT NULL,
                        interesting INTEGER NOT NULL,
                        updated_at REAL NOT NULL,
                        PRIMARY KEY (target_key, category, operator)
                    )
                """)
                conn.commit()
        except Exception as e:
            self.logger.error(f"Failed to initialize cognitive memory database: {e}")

    def claim_fuzz_attempt(
        self,
        target_key: str,
        category: str,
        fingerprint: str,
        *,
        retry_after_seconds: float = 86400.0,
    ) -> bool:
        """Atomically reserve a hashed mutation, allowing retries after a cooldown."""
        if retry_after_seconds < 0:
            raise ValueError("retry_after_seconds must be non-negative")
        now = time.time()
        with self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO fuzz_attempts
                    (target_key, category, fingerprint, outcome, attempted_at)
                VALUES (?, ?, ?, 'reserved', ?)
                ON CONFLICT(target_key, category, fingerprint) DO UPDATE SET
                    outcome='reserved', attempted_at=excluded.attempted_at
                WHERE fuzz_attempts.attempted_at < ?
                """,
                (target_key, category, fingerprint, now, now - retry_after_seconds),
            )
            return cursor.rowcount == 1

    def record_fuzz_outcome(
        self, target_key: str, category: str, fingerprint: str, outcome: str
    ) -> None:
        """Record only a status; payload bytes and credentials never enter AURA."""
        if outcome not in {
            "no_signal",
            "candidate",
            "validated",
            "rejected",
            "interesting",
            "unchanged",
            "error",
        }:
            raise ValueError("Unsupported fuzz outcome")
        with self._connection() as conn:
            conn.execute(
                """
                UPDATE fuzz_attempts SET outcome=?
                WHERE target_key=? AND category=? AND fingerprint=?
                """,
                (outcome, target_key, category, fingerprint),
            )

    def release_fuzz_attempt(self, target_key: str, category: str, fingerprint: str) -> None:
        """Release a reservation when no probe actually reached the target."""
        with self._connection() as conn:
            conn.execute(
                """
                DELETE FROM fuzz_attempts
                WHERE target_key=? AND category=? AND fingerprint=? AND outcome='reserved'
                """,
                (target_key, category, fingerprint),
            )

    def record_fuzz_feedback(
        self, target_key: str, category: str, operator: str, interesting: bool
    ) -> None:
        """Retain aggregate operator outcomes without persisting test payloads."""
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO fuzz_operator_feedback
                    (target_key, category, operator, attempts, interesting, updated_at)
                VALUES (?, ?, ?, 1, ?, ?)
                ON CONFLICT(target_key, category, operator) DO UPDATE SET
                    attempts=attempts+1,
                    interesting=interesting+excluded.interesting,
                    updated_at=excluded.updated_at
                """,
                (target_key, category, operator, int(interesting), time.time()),
            )

    def recall_fuzz_feedback(self, target_key: str, category: str) -> dict[str, tuple[int, int]]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT operator, attempts, interesting FROM fuzz_operator_feedback
                WHERE target_key=? AND category=?
                """,
                (target_key, category),
            ).fetchall()
        return {operator: (attempts, interesting) for operator, attempts, interesting in rows}

    def remember_target_dna(self, dna: TargetDNA) -> None:
        """Store or update Target DNA in memory."""
        try:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO target_dna (target, domain, tech_stack, waf_signature, rate_limit_detected, recommended_concurrency, last_scanned)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(target) DO UPDATE SET
                        domain=excluded.domain,
                        tech_stack=excluded.tech_stack,
                        waf_signature=excluded.waf_signature,
                        rate_limit_detected=excluded.rate_limit_detected,
                        recommended_concurrency=excluded.recommended_concurrency,
                        last_scanned=excluded.last_scanned
                """,
                    (
                        dna.target,
                        dna.domain,
                        json.dumps(dna.tech_stack),
                        dna.waf_signature,
                        1 if dna.rate_limit_detected else 0,
                        dna.recommended_concurrency,
                        dna.last_scanned,
                    ),
                )
                conn.commit()
            self.logger.debug(f"Remembered Target DNA for {dna.target}")
        except Exception as e:
            self.logger.error(f"Error persisting Target DNA: {e}")

    def recall_target_dna(self, target: str) -> Optional[TargetDNA]:
        """Recall target DNA context prior to scanning."""
        clean_target = target.replace("https://", "").replace("http://", "").rstrip("/")
        try:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM target_dna WHERE target = ? OR domain = ?",
                    (target, clean_target),
                )
                row = cursor.fetchone()
                if row:
                    return TargetDNA(
                        target=row[0],
                        domain=row[1],
                        tech_stack=json.loads(row[2]) if row[2] else [],
                        waf_signature=row[3],
                        rate_limit_detected=bool(row[4]),
                        recommended_concurrency=row[5],
                        last_scanned=row[6],
                    )
        except Exception as e:
            self.logger.error(f"Error recalling Target DNA: {e}")
        return None

    def crystallize_pattern(
        self,
        target: str,
        vuln_type: str,
        payload: str,
        waf_bypassed: bool = False,
        confidence: float = 0.9,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Crystallize a successful exploit payload or WAF bypass pattern."""
        digest = hashlib.sha256(f"{target}\0{vuln_type}\0{payload}".encode()).hexdigest()
        pattern_id = f"{vuln_type}:{digest}"
        meta = metadata or {}
        now = time.time()

        try:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT pattern_id, occurrences, confidence FROM cognitive_patterns
                    WHERE target = ? AND vuln_type = ? AND payload = ?
                    ORDER BY last_verified DESC LIMIT 1""",
                    (target, vuln_type, payload),
                )
                existing = cursor.fetchone()

                if existing:
                    pattern_id = existing[0]
                    occurrences = existing[1] + 1
                    new_confidence = min(1.0, existing[2] + 0.05)
                    cursor.execute(
                        """
                        UPDATE cognitive_patterns
                        SET occurrences = ?, confidence = ?, waf_bypassed = ?, last_verified = ?, metadata = ?
                        WHERE pattern_id = ?
                    """,
                        (
                            occurrences,
                            new_confidence,
                            1 if waf_bypassed else 0,
                            now,
                            json.dumps(meta),
                            pattern_id,
                        ),
                    )
                else:
                    cursor.execute(
                        """
                        INSERT INTO cognitive_patterns (pattern_id, target, vuln_type, payload, waf_bypassed, confidence, occurrences, last_verified, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            pattern_id,
                            target,
                            vuln_type,
                            payload,
                            1 if waf_bypassed else 0,
                            confidence,
                            1,
                            now,
                            json.dumps(meta),
                        ),
                    )
                conn.commit()
            self.logger.info(f"Crystallized pattern {pattern_id} for {target}")
        except Exception as e:
            self.logger.error(f"Error crystallizing cognitive pattern: {e}")

        return pattern_id

    def recall_patterns_for_target(
        self, target: str, vuln_type: Optional[str] = None
    ) -> List[CognitivePattern]:
        """Recall high-confidence crystallized patterns for a given target."""
        patterns: List[CognitivePattern] = []
        try:
            with self._connection() as conn:
                cursor = conn.cursor()
                if vuln_type:
                    cursor.execute(
                        "SELECT * FROM cognitive_patterns WHERE (target = ? OR target = '*') AND vuln_type = ? ORDER BY confidence DESC",
                        (target, vuln_type),
                    )
                else:
                    cursor.execute(
                        "SELECT * FROM cognitive_patterns WHERE target = ? OR target = '*' ORDER BY confidence DESC",
                        (target,),
                    )

                for row in cursor.fetchall():
                    patterns.append(
                        CognitivePattern(
                            pattern_id=row[0],
                            target=row[1],
                            vuln_type=row[2],
                            payload=row[3],
                            waf_bypassed=bool(row[4]),
                            confidence=row[5],
                            occurrences=row[6],
                            last_verified=row[7],
                            metadata=json.loads(row[8]) if row[8] else {},
                        )
                    )
        except Exception as e:
            self.logger.error(f"Error recalling cognitive patterns: {e}")

        return patterns

    def apply_decay(self, max_age_days: int = 30) -> int:
        """Apply memory decay: decrease confidence of unverified old patterns."""
        cutoff = time.time() - (max_age_days * 86400)
        purged = 0
        try:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE cognitive_patterns SET confidence = confidence * 0.8 WHERE last_verified < ?",
                    (cutoff,),
                )
                cursor.execute("DELETE FROM cognitive_patterns WHERE confidence < 0.2")
                purged = cursor.rowcount
                cursor.execute("DELETE FROM fuzz_attempts WHERE attempted_at < ?", (cutoff,))
                cursor.execute("DELETE FROM fuzz_operator_feedback WHERE updated_at < ?", (cutoff,))
                conn.commit()
            self.logger.info(f"Applied memory decay: purged {purged} stale patterns")
        except Exception as e:
            self.logger.error(f"Error applying memory decay: {e}")
        return purged

    def inspect_memory(self, target: Optional[str] = None) -> Dict[str, Any]:
        """Export comprehensive cognitive memory summary for CLI reporting."""
        dna_records = []
        patterns = []
        fuzz_attempt_count = 0

        try:
            with self._connection() as conn:
                cursor = conn.cursor()
                fuzz_attempt_count = cursor.execute(
                    "SELECT COUNT(*) FROM fuzz_attempts"
                ).fetchone()[0]
                if target:
                    cursor.execute("SELECT * FROM target_dna WHERE target = ?", (target,))
                else:
                    cursor.execute("SELECT * FROM target_dna LIMIT 50")

                for row in cursor.fetchall():
                    dna_records.append(
                        {
                            "target": row[0],
                            "domain": row[1],
                            "tech_stack": json.loads(row[2]) if row[2] else [],
                            "waf_signature": row[3],
                            "rate_limit_detected": bool(row[4]),
                            "recommended_concurrency": row[5],
                        }
                    )

                if target:
                    cursor.execute("SELECT * FROM cognitive_patterns WHERE target = ?", (target,))
                else:
                    cursor.execute("SELECT * FROM cognitive_patterns LIMIT 100")

                for row in cursor.fetchall():
                    patterns.append(
                        {
                            "pattern_id": row[0],
                            "target": row[1],
                            "vuln_type": row[2],
                            "payload": row[3],
                            "waf_bypassed": bool(row[4]),
                            "confidence": round(row[5], 2),
                            "occurrences": row[6],
                        }
                    )
        except Exception as e:
            self.logger.error(f"Error inspecting memory: {e}")

        return {
            "sdk_available": self._sdk_available,
            "database_path": str(self.db_path),
            "target_dna_count": len(dna_records),
            "cognitive_patterns_count": len(patterns),
            "fuzz_attempt_count": fuzz_attempt_count,
            "targets": dna_records,
            "patterns": patterns,
        }

"""
Advanced Aura Cognitive Memory Manager for SecAgent.
Integrates Aura Cognitive Memory Architecture (DNA layering, cognitive crystallization, decay & reinforcement)
with a zero-dependency local SQLite persistent storage fallback.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

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

    def _init_sqlite_schema(self) -> None:
        """Initialize local SQLite persistence tables."""
        try:
            with sqlite3.connect(self.db_path) as conn:
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
                conn.commit()
        except Exception as e:
            self.logger.error(f"Failed to initialize cognitive memory database: {e}")

    def remember_target_dna(self, dna: TargetDNA) -> None:
        """Store or update Target DNA in memory."""
        try:
            with sqlite3.connect(self.db_path) as conn:
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
            with sqlite3.connect(self.db_path) as conn:
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
        pattern_id = f"{vuln_type}:{hash(payload)}"
        meta = metadata or {}
        now = time.time()

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT occurrences, confidence FROM cognitive_patterns WHERE pattern_id = ?",
                    (pattern_id,),
                )
                existing = cursor.fetchone()

                if existing:
                    occurrences = existing[0] + 1
                    new_confidence = min(1.0, existing[1] + 0.05)
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
            with sqlite3.connect(self.db_path) as conn:
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
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE cognitive_patterns SET confidence = confidence * 0.8 WHERE last_verified < ?",
                    (cutoff,),
                )
                cursor.execute("DELETE FROM cognitive_patterns WHERE confidence < 0.2")
                purged = cursor.rowcount
                conn.commit()
            self.logger.info(f"Applied memory decay: purged {purged} stale patterns")
        except Exception as e:
            self.logger.error(f"Error applying memory decay: {e}")
        return purged

    def inspect_memory(self, target: Optional[str] = None) -> Dict[str, Any]:
        """Export comprehensive cognitive memory summary for CLI reporting."""
        dna_records = []
        patterns = []

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
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
            "targets": dna_records,
            "patterns": patterns,
        }

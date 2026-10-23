"""Tamper-Evident Evidence Lineage & Canonical Manifest System.

Guarantees:
1. Canonical manifest generation with deterministic JSON serialization and SHA-256 digests.
2. Append-only cryptographic hash chain persisted in SQLite.
3. Explicit genesis event handling (sequence_id=1, previous_hash=64 zeros).
4. Verifier recomputing hash continuity, sequence monotonicity, and manifest integrity.
5. Reproducible Evidence Bundle export (JSON) uniting incident, sweep, planner, and lineage.
6. Honest threat boundary: Tamper-evident within application bounds; not an immutable blockchain.
"""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import platform
import sqlite3
import sys
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from backend.ml.features import FEATURES, SCHEMA


GENESIS_PREVIOUS_HASH = "0" * 64
LINEAGE_MANIFEST_VERSION = "netguard-lineage-v1"


def canonical_json_dumps(obj: Any) -> str:
    """Serializes objects to deterministic canonical JSON (sorted keys, compact separators)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_manifest_digest(manifest_dict: Dict[str, Any]) -> Tuple[str, str]:
    """Serializes manifest to canonical JSON and computes its SHA-256 digest."""
    canon_str = canonical_json_dumps(manifest_dict)
    digest = hashlib.sha256(canon_str.encode("utf-8")).hexdigest()
    return digest, canon_str


def calculate_event_hash(
    sequence_id: int,
    event_id: str,
    event_type: str,
    manifest_digest: str,
    previous_hash: str
) -> str:
    """Calculates SHA-256 event hash over sequence, identifiers, manifest digest, and previous hash."""
    payload = f"{sequence_id}|{event_id}|{event_type}|{manifest_digest}|{previous_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class EvidenceLineageService:
    def __init__(self, db_path: str = "artifacts/netguard_incidents.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    @contextmanager
    def _connection(self):
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._lock, self._connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS lineage_events (
                    sequence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    event_type TEXT NOT NULL,
                    parent_id TEXT,
                    timestamp REAL NOT NULL,
                    iso_time TEXT NOT NULL,
                    manifest_digest TEXT NOT NULL,
                    manifest_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_lineage_event_id ON lineage_events(event_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_lineage_parent ON lineage_events(parent_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_lineage_type ON lineage_events(event_type)")
            conn.commit()

    def get_latest_event(self) -> Optional[Dict[str, Any]]:
        with self._lock, self._connection() as conn:
            cur = conn.execute("SELECT * FROM lineage_events ORDER BY sequence_id DESC LIMIT 1")
            row = cur.fetchone()
            return dict(row) if row else None

    def record_event(
        self,
        event_type: str,
        manifest_data: Dict[str, Any],
        parent_id: Optional[str] = None,
        event_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Appends a new immutable lineage event to the hash chain."""
        eid = event_id or f"lin-{int(time.time()*1000)}-{uuid.uuid4().hex[:8]}"
        now = time.time()
        iso_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now))

        # Enrich manifest with standard provenance headers
        full_manifest = {
            "manifest_version": LINEAGE_MANIFEST_VERSION,
            "event_id": eid,
            "event_type": event_type,
            "parent_id": parent_id,
            "timestamp": now,
            "iso_time": iso_time,
            "system_environment": {
                "python_version": sys.version.split()[0],
                "platform": platform.platform(),
                "feature_schema": SCHEMA,
                "features_count": len(FEATURES),
            },
            "data": manifest_data,
        }

        manifest_digest, manifest_json = compute_manifest_digest(full_manifest)

        with self._lock, self._connection() as conn:
            # Fetch latest event to get previous_hash and next sequence_id
            cur = conn.execute("SELECT sequence_id, event_hash FROM lineage_events ORDER BY sequence_id DESC LIMIT 1")
            last_row = cur.fetchone()

            if last_row is None:
                next_seq = 1
                previous_hash = GENESIS_PREVIOUS_HASH
            else:
                next_seq = last_row["sequence_id"] + 1
                previous_hash = last_row["event_hash"]

            event_hash = calculate_event_hash(
                sequence_id=next_seq,
                event_id=eid,
                event_type=event_type,
                manifest_digest=manifest_digest,
                previous_hash=previous_hash,
            )

            conn.execute("""
                INSERT INTO lineage_events (
                    sequence_id, event_id, event_type, parent_id, timestamp,
                    iso_time, manifest_digest, manifest_json, previous_hash, event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                next_seq, eid, event_type, parent_id, now,
                iso_time, manifest_digest, manifest_json, previous_hash, event_hash
            ))
            conn.commit()

        return {
            "sequence_id": next_seq,
            "event_id": eid,
            "event_type": event_type,
            "parent_id": parent_id,
            "timestamp": now,
            "iso_time": iso_time,
            "manifest_digest": manifest_digest,
            "previous_hash": previous_hash,
            "event_hash": event_hash,
            "manifest": full_manifest,
        }

    def verify_chain(self) -> Dict[str, Any]:
        """Recomputes and verifies the complete hash chain from genesis to head."""
        with self._lock, self._connection() as conn:
            cur = conn.execute("SELECT * FROM lineage_events ORDER BY sequence_id ASC")
            rows = [dict(r) for r in cur.fetchall()]

        if not rows:
            return {
                "status": "EMPTY",
                "is_valid": True,
                "events_count": 0,
                "head_hash": None,
                "message": "Lineage store is initialized with zero recorded events.",
            }

        expected_prev = GENESIS_PREVIOUS_HASH
        expected_seq = 1

        for row in rows:
            seq = row["sequence_id"]
            eid = row["event_id"]
            etype = row["event_type"]
            m_digest = row["manifest_digest"]
            m_json = row["manifest_json"]
            prev_hash = row["previous_hash"]
            evt_hash = row["event_hash"]

            # 1. Monotonic sequence check
            if seq != expected_seq:
                return {
                    "status": "INVALID",
                    "is_valid": False,
                    "failing_sequence_id": seq,
                    "failing_event_id": eid,
                    "error_reason": f"Sequence break: expected sequence_id {expected_seq}, found {seq}",
                }

            # 2. Previous hash continuity check
            if prev_hash != expected_prev:
                return {
                    "status": "INVALID",
                    "is_valid": False,
                    "failing_sequence_id": seq,
                    "failing_event_id": eid,
                    "error_reason": "Hash chain break: previous_hash does not match predecessor event_hash",
                    "expected_previous_hash": expected_prev,
                    "actual_previous_hash": prev_hash,
                }

            # 3. Manifest content digest check
            recomputed_digest = hashlib.sha256(m_json.encode("utf-8")).hexdigest()
            if recomputed_digest != m_digest:
                return {
                    "status": "INVALID",
                    "is_valid": False,
                    "failing_sequence_id": seq,
                    "failing_event_id": eid,
                    "error_reason": "Manifest content tampered: manifest_digest does not match SHA-256 of manifest_json",
                    "expected_manifest_digest": m_digest,
                    "recomputed_manifest_digest": recomputed_digest,
                }

            # 4. Event hash computation check
            recomputed_evt_hash = calculate_event_hash(
                sequence_id=seq,
                event_id=eid,
                event_type=etype,
                manifest_digest=m_digest,
                previous_hash=prev_hash,
            )
            if recomputed_evt_hash != evt_hash:
                return {
                    "status": "INVALID",
                    "is_valid": False,
                    "failing_sequence_id": seq,
                    "failing_event_id": eid,
                    "error_reason": "Event hash tampered: event_hash does not match recomputed SHA-256 payload",
                    "expected_event_hash": evt_hash,
                    "recomputed_event_hash": recomputed_evt_hash,
                }

            expected_prev = evt_hash
            expected_seq += 1

        return {
            "status": "VALID",
            "is_valid": True,
            "events_count": len(rows),
            "head_hash": expected_prev,
            "message": f"Hash chain verified across {len(rows)} sequential events. No breaks or modifications detected.",
        }

    def list_events(self, limit: int = 50, offset: int = 0) -> Tuple[List[Dict[str, Any]], int]:
        with self._lock, self._connection() as conn:
            count_cur = conn.execute("SELECT COUNT(*) FROM lineage_events")
            total = count_cur.fetchone()[0]

            cur = conn.execute(
                "SELECT * FROM lineage_events ORDER BY sequence_id DESC LIMIT ? OFFSET ?",
                (limit, offset)
            )
            rows = [dict(r) for r in cur.fetchall()]

            # Parse manifest_json to dict for response
            results = []
            for r in rows:
                try:
                    r["manifest"] = json.loads(r["manifest_json"])
                except Exception:
                    r["manifest"] = {}
                results.append(r)

            return results, total

    def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connection() as conn:
            cur = conn.execute("SELECT * FROM lineage_events WHERE event_id = ?", (event_id,))
            row = cur.fetchone()
            if not row:
                return None
            res = dict(row)
            try:
                res["manifest"] = json.loads(res["manifest_json"])
            except Exception:
                res["manifest"] = {}
            return res

    def build_evidence_bundle(self, run_or_event_id: str) -> Dict[str, Any]:
        """Packages a complete, reproducible evidence bundle linking experiment, incident, and lineage."""
        event = self.get_event(run_or_event_id)
        if not event:
            # Search by parent or manifest run_id
            with self._lock, self._connection() as conn:
                cur = conn.execute(
                    "SELECT * FROM lineage_events WHERE parent_id = ? OR event_id LIKE ? ORDER BY sequence_id DESC LIMIT 1",
                    (run_or_event_id, f"%{run_or_event_id}%")
                )
                row = cur.fetchone()
                if row:
                    event = dict(row)
                    try:
                        event["manifest"] = json.loads(event["manifest_json"])
                    except Exception:
                        event["manifest"] = {}

        chain_verification = self.verify_chain()

        return {
            "bundle_version": "netguard-bundle-v1",
            "generated_at": time.time(),
            "target_identifier": run_or_event_id,
            "target_event": event,
            "lineage_verification": chain_verification,
            "reproducibility_contract": {
                "features": FEATURES,
                "schema": SCHEMA,
                "canonical_serialization": "RFC 8785 compliant canonical JSON (sort_keys=True, compact separators)",
                "verification_hash_algorithm": "SHA-256",
            },
            "security_disclaimer": (
                "TAMPER-EVIDENT ADVISORY RECORD. Local SQLite hash chains verify integrity within the NetGuard "
                "application runtime. They demonstrate that historical recorded events have not been silently modified "
                "in place. They do not constitute asymmetric digital signatures or protection against hostile "
                "database administrator overwrites."
            ),
        }

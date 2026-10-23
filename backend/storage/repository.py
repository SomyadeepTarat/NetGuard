"""SQLite Incident Repository & Evidence Passport Persistence.

Persists complete Evidence Passports for network incidents without retaining raw payloads.
Supports JSON/CSV export, query filtering, bounded retention, and IP pseudonymization.
"""
from contextlib import contextmanager
import csv
import io
import json
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple


def pseudonymize_ip(ip: Optional[str]) -> str:
    """Masks host octets/hextets for privacy-safe reporting and demonstrations."""
    if not ip or ip == "-":
        return "-"
    # IPv4 mask: 192.168.1.10 -> 192.168.1.xxx
    if "." in ip:
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
    # IPv6 mask: 2001:db8::1 -> 2001:db8::xxxx
    if ":" in ip:
        parts = ip.split(":")
        return ":".join(parts[:3]) + ":...:xxxx"
    return ip


class IncidentRepository:
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
                CREATE TABLE IF NOT EXISTS incidents (
                    alert_id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    iso_time TEXT NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    protocol TEXT NOT NULL,
                    detector_class TEXT NOT NULL,
                    detector_score REAL,
                    is_calibrated INTEGER DEFAULT 0,
                    decision TEXT NOT NULL,
                    model_scope TEXT,
                    rule_triggers_json TEXT,
                    anomaly_json TEXT,
                    capture_quality_json TEXT,
                    evidence_json TEXT,
                    fragility_json TEXT,
                    why_flagged TEXT,
                    what_remains_uncertain TEXT,
                    recommended_steps_json TEXT,
                    provenance TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_class ON incidents(detector_class)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_source ON incidents(source_ip)")
            conn.commit()

    def save_incident(self, incident: dict) -> str:
        alert_id = incident.get("alert_id") or f"alt-{int(time.time()*1000)}-{uuid_tail()}"
        ts = incident.get("timestamp", time.time())
        iso_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))

        why_flagged = incident.get("why_flagged") or self._generate_why_flagged(incident)
        what_remains_uncertain = incident.get("what_remains_uncertain") or self._generate_uncertainty(incident)
        steps = incident.get("recommended_steps") or self._generate_recommended_steps(incident)

        with self._lock, self._connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO incidents (
                    alert_id, timestamp, iso_time, source_ip, destination_ip, protocol,
                    detector_class, detector_score, is_calibrated, decision, model_scope,
                    rule_triggers_json, anomaly_json, capture_quality_json, evidence_json,
                    fragility_json, why_flagged, what_remains_uncertain, recommended_steps_json,
                    provenance
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_id,
                ts,
                iso_time,
                incident.get("source_ip"),
                incident.get("destination_ip"),
                incident.get("protocol", "TCP"),
                incident.get("detector_class", "UNKNOWN"),
                incident.get("detector_score"),
                1 if incident.get("is_calibrated") else 0,
                incident.get("decision", "SUSPECTED"),
                incident.get("model_scope", "synthetic-demo"),
                json.dumps(incident.get("rule_triggers", [])),
                json.dumps(incident.get("anomaly", {})),
                json.dumps(incident.get("capture_quality", {})),
                json.dumps(incident.get("evidence", {})),
                json.dumps(incident.get("fragility", {})),
                why_flagged,
                what_remains_uncertain,
                json.dumps(steps),
                incident.get("provenance", "offline-replay")
            ))
            conn.commit()
        return alert_id

    def get_incidents(
        self,
        limit: int = 50,
        offset: int = 0,
        class_filter: Optional[str] = None,
        severity_filter: Optional[str] = None,
        search: Optional[str] = None,
        redact_ips: bool = False
    ) -> Tuple[List[dict], int]:
        query = "SELECT * FROM incidents WHERE 1=1"
        count_query = "SELECT COUNT(*) FROM incidents WHERE 1=1"
        params: List[Any] = []

        if class_filter:
            query += " AND detector_class = ?"
            count_query += " AND detector_class = ?"
            params.append(class_filter)
        if severity_filter:
            query += " AND decision = ?"
            count_query += " AND decision = ?"
            params.append(severity_filter)
        if search:
            query += " AND (source_ip LIKE ? OR destination_ip LIKE ? OR alert_id LIKE ?)"
            count_query += " AND (source_ip LIKE ? OR destination_ip LIKE ? OR alert_id LIKE ?)"
            term = f"%{search}%"
            params.extend([term, term, term])

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        exec_params = list(params) + [limit, offset]

        with self._lock, self._connection() as conn:
            total = conn.execute(count_query, params).fetchone()[0]
            rows = conn.execute(query, exec_params).fetchall()
            results = [self._row_to_dict(r, redact_ips) for r in rows]
            return results, total

    def get_incident_by_id(self, alert_id: str, redact_ips: bool = False) -> Optional[dict]:
        with self._lock, self._connection() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE alert_id = ?", (alert_id,)).fetchone()
            return self._row_to_dict(row, redact_ips) if row else None

    def export_json(self, redact_ips: bool = False) -> str:
        incidents, _ = self.get_incidents(limit=10000, redact_ips=redact_ips)
        return json.dumps({
            "export_schema": "netguard-evidence-passport-v1",
            "exported_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "total_records": len(incidents),
            "ip_pseudonymized": redact_ips,
            "incidents": incidents
        }, indent=2)

    def export_csv(self, redact_ips: bool = False) -> str:
        incidents, _ = self.get_incidents(limit=10000, redact_ips=redact_ips)
        output = io.StringIO()
        fieldnames = [
            "alert_id", "iso_time", "source_ip", "destination_ip", "protocol",
            "detector_class", "detector_score", "decision", "model_scope",
            "why_flagged", "what_remains_uncertain"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for inc in incidents:
            writer.writerow(inc)
        return output.getvalue()

    def delete_older_than(self, seconds: float) -> int:
        cutoff = time.time() - seconds
        with self._lock, self._connection() as conn:
            cursor = conn.execute("DELETE FROM incidents WHERE timestamp < ?", (cutoff,))
            conn.commit()
            return cursor.rowcount

    def _row_to_dict(self, row: sqlite3.Row, redact_ips: bool) -> dict:
        src = pseudonymize_ip(row["source_ip"]) if redact_ips else row["source_ip"]
        dst = pseudonymize_ip(row["destination_ip"]) if redact_ips else row["destination_ip"]

        return {
            "alert_id": row["alert_id"],
            "timestamp": row["timestamp"],
            "iso_time": row["iso_time"],
            "source_ip": src,
            "destination_ip": dst,
            "protocol": row["protocol"],
            "detector_class": row["detector_class"],
            "detector_score": row["detector_score"],
            "is_calibrated": bool(row["is_calibrated"]),
            "decision": row["decision"],
            "model_scope": row["model_scope"],
            "rule_triggers": json.loads(row["rule_triggers_json"] or "[]"),
            "anomaly": json.loads(row["anomaly_json"] or "{}"),
            "capture_quality": json.loads(row["capture_quality_json"] or "{}"),
            "evidence": json.loads(row["evidence_json"] or "{}"),
            "fragility": json.loads(row["fragility_json"] or "{}"),
            "why_flagged": row["why_flagged"],
            "what_remains_uncertain": row["what_remains_uncertain"],
            "recommended_steps": json.loads(row["recommended_steps_json"] or "[]"),
            "provenance": row["provenance"],
        }

    def _generate_why_flagged(self, inc: dict) -> str:
        cls = inc.get("detector_class", "UNKNOWN")
        score = inc.get("detector_score")
        evidence = inc.get("evidence", {})
        score_text = f"{score:.3f}" if score is not None else "N/A"

        if cls == "PORT_SCAN":
            return f"Flagged as PORT_SCAN (score={score_text}): Observed {evidence.get('unique_ports', '?')} unique destination ports with outbound SYN rate of {evidence.get('syn_rate', '?')} pkts/s."
        if cls == "SYN_FLOOD":
            return f"Flagged as SYN_FLOOD (score={score_text}): Observed high SYN transmission rate ({evidence.get('syn_rate', '?')} pkts/s) with handshake completion ratio of {evidence.get('completed_fraction', '?')}."
        if cls == "TRAFFIC_FLOOD":
            return f"Flagged as TRAFFIC_FLOOD (score={score_text}): Sustained high byte rate of {evidence.get('bytes_per_second', '?')} bytes/sec."
        return f"Flagged as {cls} (score={score_text}) based on pattern features."

    def _generate_uncertainty(self, inc: dict) -> str:
        quality = inc.get("capture_quality", {})
        caveats = []
        if quality.get("overall_status") == "DEGRADED":
            caveats.append("Capture quality is degraded (internal drops or state evictions recorded).")
        caveats.append("Passive packet headers observed; encrypted application payload contents are unobserved.")
        caveats.append("Scores are uncalibrated classifier outputs, not proof of real-world attack intent.")
        return " | ".join(caveats)

    def _generate_recommended_steps(self, inc: dict) -> List[str]:
        src = inc.get("source_ip", "source host")
        return [
            f"Inspect local host authentication and process logs for {src}.",
            f"Review firewall and router connection tables for corresponding outbound connections from {src}.",
            "Verify sensor capture quality to rule out asymmetric routing or monitoring TAP packet loss.",
            "Run Counterfactual Replay Lab on this time window to test observation-loss sensitivity.",
            "Do NOT issue automated blocking or active probes without manual analyst confirmation."
        ]


def uuid_tail() -> str:
    import uuid
    return uuid.uuid4().hex[:6]

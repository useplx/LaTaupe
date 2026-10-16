from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path


class Settings:
    def __init__(self, connection: sqlite3.Connection, lock: threading.RLock) -> None:
        self._connection = connection
        self._lock = lock

    def get(self) -> dict[str, str]:
        with self._lock:
            rows = self._connection.execute("SELECT key,value FROM settings")
            return {row[0]: row[1] for row in rows}

    def set(self, values: dict[str, str]) -> None:
        with self._lock, self._connection:
            self._connection.executemany(
                "INSERT INTO settings(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                values.items(),
            )


class Report:
    def __init__(self, connection: sqlite3.Connection, lock: threading.RLock) -> None:
        self._connection = connection
        self._lock = lock

    def pending(self, limit: int = 20, retry: bool = False) -> list[int]:
        states = "'pending','analyzing','unavailable','failed'" if retry else "'pending'"
        with self._lock:
            rows = self._connection.execute(
                f"SELECT mitigation_id FROM reports WHERE status IN ({states}) ORDER BY id LIMIT ?",
                (limit,),
            ).fetchall()
        return [int(row[0]) for row in rows]

    def list(self, limit: int = 100) -> list[dict[str, object]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT r.*,m.method,m.route,m.attack_type,m.risk,m.count,m.last_seen "
                "FROM reports r JOIN mitigations m ON m.id=r.mitigation_id "
                "ORDER BY r.updated_at DESC LIMIT ?", (min(max(limit, 1), 1000),)
            ).fetchall()
        result = [dict(row) for row in rows]
        for row in result:
            row["sources"] = json.loads(str(row["sources"]))
        return result

    def set(self, mitigation_id: int, status: str, *, content: str | None = None,
            verdict: str | None = None, sources: list[dict[str, str]] | None = None,
            error: str | None = None) -> None:
        now = datetime.now(UTC).isoformat()
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE reports SET updated_at=?,status=?,content=?,verdict=?,sources=?,error=? "
                "WHERE mitigation_id=?",
                (now, status, content, verdict, json.dumps(sources or []), error, mitigation_id),
            )
            self._connection.execute(
                "UPDATE mitigations SET report_status=? WHERE id=?", (status, mitigation_id)
            )


class Store:
    def __init__(self, path: str | Path, salt: str = "lataupe-local") -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(destination, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._salt = salt
        with self._connection:
            self._connection.executescript("""
                CREATE TABLE IF NOT EXISTS mitigations (
                    id INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE,
                    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, client TEXT NOT NULL,
                    method TEXT NOT NULL, route TEXT NOT NULL, attack_type TEXT NOT NULL,
                    risk REAL NOT NULL, action TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 1,
                    latency_ms REAL NOT NULL, sample TEXT NOT NULL, features TEXT NOT NULL,
                    report_status TEXT NOT NULL DEFAULT 'pending'
                );
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY, mitigation_id INTEGER NOT NULL UNIQUE,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, status TEXT NOT NULL,
                    verdict TEXT, content TEXT, sources TEXT NOT NULL DEFAULT '[]', error TEXT,
                    FOREIGN KEY(mitigation_id) REFERENCES mitigations(id)
                );
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS telemetry (
                    id INTEGER PRIMARY KEY CHECK(id=1), requests INTEGER NOT NULL,
                    blocked INTEGER NOT NULL, risk_sum REAL NOT NULL, latency_sum REAL NOT NULL
                );
                INSERT OR IGNORE INTO telemetry(id,requests,blocked,risk_sum,latency_sum)
                VALUES(1,0,0,0,0);
            """)
        self.settings = Settings(self._connection, self._lock)
        self.report = Report(self._connection, self._lock)

    def pseudonym(self, client: str) -> str:
        digest = hashlib.blake2s(f"{self._salt}:{client}".encode(), digest_size=6).hexdigest()
        return f"client-{digest}"

    def record(self, *, fingerprint: str, client: str, method: str, route: str,
               attack_type: str, risk: float, action: str, latency_ms: float,
               sample: str, features: dict[str, int | float]) -> tuple[int, bool]:
        now = datetime.now(UTC).isoformat()
        with self._lock, self._connection:
            self._add(risk, latency_ms, action == "block")
            row = self._connection.execute(
                "SELECT id FROM mitigations WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            if row:
                self._connection.execute(
                    "UPDATE mitigations SET last_seen=?, client=?, risk=MAX(risk,?), action=?, "
                    "count=count+1, latency_ms=?, sample=?, features=? WHERE id=?",
                    (now, self.pseudonym(client), risk, action, latency_ms, sample,
                     json.dumps(features), row["id"]),
                )
                return int(row["id"]), False
            cursor = self._connection.execute(
                "INSERT INTO mitigations(fingerprint,first_seen,last_seen,client,method,route,"
                "attack_type,risk,action,latency_ms,sample,features) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (fingerprint, now, now, self.pseudonym(client), method, route, attack_type,
                 risk, action, latency_ms, sample, json.dumps(features)),
            )
            mitigation_id = int(cursor.lastrowid)
            self._connection.execute(
                "INSERT INTO reports(mitigation_id,created_at,updated_at,status) VALUES(?,?,?,'pending')",
                (mitigation_id, now, now),
            )
            return mitigation_id, True

    def allow(self, risk: float, latency_ms: float) -> None:
        with self._lock, self._connection:
            self._add(risk, latency_ms, False)

    def _add(self, risk: float, latency_ms: float, blocked: bool) -> None:
        self._connection.execute(
            "UPDATE telemetry SET requests=requests+1,blocked=blocked+?,risk_sum=risk_sum+?,latency_sum=latency_sum+? WHERE id=1",
            (int(blocked), risk, latency_ms),
        )

    def mitigations(self, limit: int = 100) -> list[dict[str, object]]:
        limit = min(max(limit, 1), 1000)
        with self._lock:
            rows = self._connection.execute(
                "SELECT id,last_seen,first_seen,client,method,route,attack_type,risk,action,count,"
                "latency_ms,report_status FROM mitigations ORDER BY last_seen DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def mitigation(self, mitigation_id: int) -> dict[str, object] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM mitigations WHERE id=?", (mitigation_id,)
            ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["features"] = json.loads(str(result["features"]))
        return result

    def summary(self) -> dict[str, object]:
        with self._lock:
            unique = self._connection.execute("SELECT COUNT(*) FROM mitigations").fetchone()[0]
            totals = self._connection.execute(
                "SELECT requests,blocked,risk_sum,latency_sum FROM telemetry WHERE id=1"
            ).fetchone()
            types = self._connection.execute(
                "SELECT attack_type,SUM(count) count FROM mitigations GROUP BY attack_type ORDER BY count DESC"
            ).fetchall()
            timeline = self._connection.execute(
                "SELECT substr(last_seen,1,13) hour,SUM(count) count FROM mitigations GROUP BY hour ORDER BY hour DESC LIMIT 24"
            ).fetchall()
        requests = int(totals[0])
        return {"unique_mitigations": unique, "requests": requests, "blocked": totals[1],
                "average_risk": totals[2] / max(requests, 1),
                "average_latency_ms": totals[3] / max(requests, 1),
                "attack_types": {row[0]: row[1] for row in types},
                "timeline": list(reversed([dict(row) for row in timeline])),
                "updated_at": datetime.now(UTC).isoformat()}

    def close(self) -> None:
        with self._lock:
            self._connection.close()

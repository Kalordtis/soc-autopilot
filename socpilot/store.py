"""SQLite case store, so results can be queried with plain SQL (see sql/hunting_queries.sql)."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import Event, Incident
from .vulns import Finding

SCHEMA = """
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS incidents;
DROP TABLE IF EXISTS vulns;
CREATE TABLE events (
    ts TEXT, source TEXT, event_type TEXT, user TEXT, src_ip TEXT, host TEXT,
    country TEXT, city TEXT, extra TEXT
);
CREATE TABLE incidents (
    incident_id TEXT PRIMARY KEY, title TEXT, severity TEXT, risk_score INTEGER,
    first_seen TEXT, last_seen TEXT, entities TEXT, mitre TEXT, summary TEXT
);
CREATE TABLE alerts (
    alert_id TEXT PRIMARY KEY, incident_id TEXT REFERENCES incidents(incident_id),
    rule_id TEXT, title TEXT, severity TEXT, risk_score INTEGER, mitre TEXT,
    first_seen TEXT, last_seen TEXT, entities TEXT, evidence TEXT, actions TEXT, enrichment TEXT
);
CREATE TABLE vulns (
    asset TEXT, hostname TEXT, cve TEXT, title TEXT, cvss REAL, epss REAL, in_kev INTEGER,
    internet_facing INTEGER, asset_criticality INTEGER, score INTEGER, priority TEXT,
    first_detected TEXT, due_date TEXT, rationale TEXT
);
CREATE INDEX idx_events_ip ON events(src_ip);
CREATE INDEX idx_events_user ON events(user);
"""


def save(db_path: str | Path, events: list[Event], incidents: list[Incident], findings: list[Finding]) -> None:
    con = sqlite3.connect(db_path)
    try:
        con.executescript(SCHEMA)
        con.executemany(
            "INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)",
            [(e.timestamp.isoformat(), e.source, e.event_type, e.user, e.src_ip, e.host,
              e.country, e.city, json.dumps(e.extra)) for e in events],
        )
        for inc in incidents:
            con.execute(
                "INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?)",
                (inc.incident_id, inc.title, inc.severity, inc.risk_score, inc.first_seen.isoformat(),
                 inc.last_seen.isoformat(), json.dumps(inc.entities), json.dumps(inc.mitre), inc.summary),
            )
            for a in inc.alerts:
                con.execute(
                    "INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (a.alert_id, inc.incident_id, a.rule_id, a.title, a.severity, a.risk_score,
                     json.dumps(a.mitre), a.first_seen.isoformat(), a.last_seen.isoformat(),
                     json.dumps(a.entities), json.dumps(a.evidence), json.dumps(a.actions),
                     json.dumps(a.enrichment)),
                )
        con.executemany(
            "INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [(f.asset, f.hostname, f.cve, f.title, f.cvss, f.epss, int(f.in_kev), int(f.internet_facing),
              f.asset_criticality, f.score, f.priority, f.first_detected.isoformat(),
              f.due_date.isoformat() if f.due_date else None, f.rationale) for f in findings],
        )
        con.commit()
    finally:
        con.close()

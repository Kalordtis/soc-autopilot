"""Core data models shared by every stage of the pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any


@dataclass
class Event:
    """A normalized security event. Every parser emits these, so detections
    never need to know which log format the data came from."""

    timestamp: datetime          # always timezone-aware UTC
    source: str                  # "linux_auth" | "windows" | "cloud_signin"
    event_type: str              # auth_failure, auth_success, mfa_denied, mfa_approved,
                                 # user_created, group_member_added
    user: str | None = None
    src_ip: str | None = None
    host: str | None = None
    country: str | None = None
    city: str | None = None
    lat: float | None = None
    lon: float | None = None
    raw: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        parts = [self.timestamp.strftime("%Y-%m-%d %H:%M:%S"), self.event_type]
        if self.user:
            parts.append(f"user={self.user}")
        if self.src_ip:
            parts.append(f"ip={self.src_ip}")
        if self.host:
            parts.append(f"host={self.host}")
        if self.city or self.country:
            parts.append(f"loc={self.city or '?'},{self.country or '?'}")
        for k, v in self.extra.items():
            parts.append(f"{k}={v}")
        return " ".join(parts)


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str                # low | medium | high | critical
    mitre: list[str]
    first_seen: datetime
    last_seen: datetime
    entities: dict[str, list[str]]   # {"user": [...], "ip": [...], "host": [...]}
    evidence: list[str]
    actions: list[str]
    description: str = ""
    risk_score: int = 0
    enrichment: dict[str, Any] = field(default_factory=dict)
    alert_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["first_seen"] = self.first_seen.isoformat()
        d["last_seen"] = self.last_seen.isoformat()
        return d


@dataclass
class Incident:
    incident_id: str
    alerts: list[Alert]
    title: str = ""
    severity: str = "low"
    risk_score: int = 0
    summary: str = ""

    @property
    def entities(self) -> dict[str, list[str]]:
        merged: dict[str, set[str]] = {}
        for a in self.alerts:
            for k, vals in a.entities.items():
                merged.setdefault(k, set()).update(vals)
        return {k: sorted(v) for k, v in merged.items()}

    @property
    def mitre(self) -> list[str]:
        return sorted({t for a in self.alerts for t in a.mitre})

    @property
    def first_seen(self) -> datetime:
        return min(a.first_seen for a in self.alerts)

    @property
    def last_seen(self) -> datetime:
        return max(a.last_seen for a in self.alerts)


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

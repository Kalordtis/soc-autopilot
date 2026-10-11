"""Enrichment, risk scoring and incident correlation."""
from __future__ import annotations

import csv
import ipaddress
from pathlib import Path

from .models import SEVERITY_ORDER, Alert, Incident

SEVERITY_BASE = {"low": 20, "medium": 40, "high": 60, "critical": 80}

MITRE_NAMES = {
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1078": "Valid Accounts",
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1621": "Multi-Factor Authentication Request Generation",
    "T1136.001": "Create Account: Local Account",
    "T1098": "Account Manipulation",
}


def load_threat_intel(path: str | Path) -> dict[str, dict]:
    """CSV with columns: indicator,type,confidence,source,tags"""
    p = Path(path)
    if not p.exists():
        return {}
    with p.open(newline="", encoding="utf-8") as f:
        return {row["indicator"].strip(): row for row in csv.DictReader(f)}


INTERNAL_NETS = [ipaddress.ip_network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10")]


def ip_context(ip: str) -> str:
    """Classify an IP. We check RFC 1918 explicitly because Python's `is_private`
    also returns True for documentation ranges (203.0.113.0/24 etc.) used in samples."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    if any(addr in net for net in INTERNAL_NETS if net.version == addr.version):
        return "internal"
    return "external"


def enrich_and_score(alerts: list[Alert], threat_intel: dict[str, dict], settings: dict) -> list[Alert]:
    privileged = {u.lower() for u in settings.get("privileged_users", [])}
    for a in alerts:
        score = SEVERITY_BASE.get(a.severity, 20)
        reasons = [f"base {a.severity} = {score}"]
        ti_hits = []
        for ip in a.entities.get("ip", []):
            if hit := threat_intel.get(ip):
                ti_hits.append({"ip": ip, **hit})
        if ti_hits:
            bump = 15 if any(int(h.get("confidence", 0)) >= 80 for h in ti_hits) else 8
            score += bump
            reasons.append(f"threat-intel match +{bump}")
        priv_hits = [u for u in a.entities.get("user", []) if u.lower() in privileged]
        if priv_hits:
            score += 10
            reasons.append("privileged account +10")
        ext = [ip for ip in a.entities.get("ip", []) if ip_context(ip) == "external"]
        if ext:
            score += 5
            reasons.append("external source +5")
        a.risk_score = min(score, 100)
        a.enrichment = {
            "threat_intel": ti_hits,
            "privileged_accounts": priv_hits,
            "ip_context": {ip: ip_context(ip) for ip in a.entities.get("ip", [])},
            "mitre_names": {t: MITRE_NAMES.get(t, "") for t in a.mitre},
            "score_reasons": reasons,
        }
    return alerts


def correlate(alerts: list[Alert]) -> list[Incident]:
    """Group alerts into incidents when they share a user or IP (union-find).
    Analysts triage incidents, not 40 separate alerts about the same attacker."""
    parent = list(range(len(alerts)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[tuple[str, str], int] = {}
    for i, a in enumerate(alerts):
        for kind in ("user", "ip"):
            for val in a.entities.get(kind, []):
                key = (kind, val.lower())
                if key in owner:
                    parent[find(i)] = find(owner[key])
                else:
                    owner[key] = i

    groups: dict[int, list[Alert]] = {}
    for i, a in enumerate(alerts):
        groups.setdefault(find(i), []).append(a)

    incidents = []
    for members in groups.values():
        members.sort(key=lambda a: a.first_seen)
        top = max(members, key=lambda a: (SEVERITY_ORDER[a.severity], a.risk_score))
        # risk of an incident = its worst alert, plus a little for each extra corroborating signal
        risk = min(100, top.risk_score + 5 * (len({a.rule_id for a in members}) - 1))
        inc = Incident(incident_id="", alerts=members, title=top.title, severity=top.severity, risk_score=risk)
        if len(members) > 1:
            inc.title = f"{top.title} (+{len(members) - 1} related)"
        incidents.append(inc)

    incidents.sort(key=lambda i: (-i.risk_score, i.first_seen))
    for n, inc in enumerate(incidents, 1):
        inc.incident_id = f"INC-{n:04d}"
    return incidents

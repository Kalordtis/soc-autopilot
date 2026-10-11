"""Risk-based vulnerability prioritization.

CVSS alone says how bad a bug *could* be. Real programs also ask:
  * Is it being exploited right now?        -> CISA KEV catalog
  * How likely is exploitation soon?        -> FIRST EPSS score (0-1)
  * Can an attacker reach it / does it matter? -> internet exposure, asset criticality
This module blends all four into a 0-100 priority and a remediation SLA.
"""
from __future__ import annotations

import csv
import json
import urllib.request
from dataclasses import dataclass, asdict
from datetime import date, timedelta
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={cves}"

# priority bucket -> (minimum score, remediation SLA in days)
BUCKETS = [("P1", 75, 7), ("P2", 55, 30), ("P3", 35, 60), ("P4", 0, 90)]


@dataclass
class Finding:
    asset: str
    hostname: str
    cve: str
    title: str
    cvss: float
    internet_facing: bool
    asset_criticality: int        # 1 = low, 2 = medium, 3 = crown jewel
    first_detected: date
    in_kev: bool = False
    kev_ransomware: bool = False
    epss: float = 0.0
    epss_percentile: float = 0.0
    score: int = 0
    priority: str = ""
    due_date: date | None = None
    rationale: str = ""

    def to_dict(self):
        d = asdict(self)
        d["first_detected"] = self.first_detected.isoformat()
        d["due_date"] = self.due_date.isoformat() if self.due_date else None
        return d


def load_scan(path: str | Path) -> list[Finding]:
    out = []
    with Path(path).open(newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            out.append(Finding(
                asset=r["asset"], hostname=r["hostname"], cve=r["cve"].strip().upper(), title=r["title"],
                cvss=float(r["cvss"]), internet_facing=r["internet_facing"].strip().lower() in ("1", "true", "yes"),
                asset_criticality=int(r["asset_criticality"]),
                first_detected=date.fromisoformat(r["first_detected"]),
            ))
    return out


def load_kev(path: str | Path | None = None, live: bool = False) -> dict[str, dict]:
    if live:
        with urllib.request.urlopen(KEV_URL, timeout=30) as resp:
            data = json.load(resp)
    else:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {v["cveID"].upper(): v for v in data.get("vulnerabilities", [])}


def load_epss(path: str | Path | None = None, cves: list[str] | None = None, live: bool = False) -> dict[str, tuple[float, float]]:
    out: dict[str, tuple[float, float]] = {}
    if live and cves:
        for i in range(0, len(cves), 100):   # the API accepts comma-separated batches
            url = EPSS_URL.format(cves=",".join(cves[i:i + 100]))
            with urllib.request.urlopen(url, timeout=30) as resp:
                for row in json.load(resp).get("data", []):
                    out[row["cve"].upper()] = (float(row["epss"]), float(row["percentile"]))
        return out
    with Path(path).open(newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            out[r["cve"].strip().upper()] = (float(r["epss"]), float(r["percentile"]))
    return out


def score_finding(f: Finding) -> Finding:
    parts = []
    s = f.cvss / 10 * 30
    parts.append(f"CVSS {f.cvss} -> {s:.0f}")
    e = f.epss * 25
    parts.append(f"EPSS {f.epss:.2f} -> {e:.0f}")
    s += e
    if f.in_kev:
        s += 25
        parts.append("in CISA KEV +25")
        if f.kev_ransomware:
            s += 5
            parts.append("ransomware use +5")
    if f.internet_facing:
        s += 10
        parts.append("internet-facing +10")
    crit = {1: 0, 2: 3, 3: 7}.get(f.asset_criticality, 0)
    if crit:
        s += crit
        parts.append(f"asset criticality {f.asset_criticality} +{crit}")
    f.score = min(round(s), 100)
    for name, floor, sla in BUCKETS:
        if f.score >= floor:
            f.priority = name
            f.due_date = f.first_detected + timedelta(days=sla)
            break
    # Policy override: anything actively exploited AND internet-facing is P1 regardless of math.
    if f.in_kev and f.internet_facing and f.priority != "P1":
        f.priority, f.due_date = "P1", f.first_detected + timedelta(days=7)
        parts.append("override: KEV + internet-facing => P1")
    f.rationale = "; ".join(parts)
    return f


def prioritize(scan_path, kev_path=None, epss_path=None, live=False) -> list[Finding]:
    findings = load_scan(scan_path)
    kev = load_kev(kev_path, live=live)
    epss = load_epss(epss_path, cves=sorted({f.cve for f in findings}), live=live)
    for f in findings:
        if k := kev.get(f.cve):
            f.in_kev = True
            f.kev_ransomware = str(k.get("knownRansomwareCampaignUse", "")).lower() == "known"
        f.epss, f.epss_percentile = epss.get(f.cve, (0.0, 0.0))
        score_finding(f)
    return sorted(findings, key=lambda f: (-f.score, f.due_date or date.max))


def overdue(findings: list[Finding], today: date) -> list[Finding]:
    return [f for f in findings if f.due_date and f.due_date < today]

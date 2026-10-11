"""Command line entry point.

    python -m socpilot run   --data data/sample --out out          # full pipeline
    python -m socpilot run   --data data/sample --out out --ai     # + LLM summaries (needs ANTHROPIC_API_KEY)
    python -m socpilot vulns --data data/sample --live              # vuln queue with live CISA KEV + FIRST EPSS
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import date
from pathlib import Path

from . import ai_summary, detections, enrich, parsers, report, store, vulns


def _vuln_paths(data: Path):
    return data / "vuln_scan.csv", data / "kev_sample.json", data / "epss_sample.csv"


def cmd_run(args) -> int:
    data, out = Path(args.data), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    today = date.fromisoformat(args.today) if args.today else date.today()

    events = parsers.load_directory(data, year=args.year)
    print(f"[1/6] Parsed {len(events)} events from {data}")

    settings, _ = detections.load_rules(args.rules)
    alerts = detections.run_detections(events, args.rules)
    print(f"[2/6] {len(alerts)} alerts from {len({a.rule_id for a in alerts})} rules")

    ti = enrich.load_threat_intel(data / "threat_intel.csv")
    enrich.enrich_and_score(alerts, ti, settings)
    incidents = enrich.correlate(alerts)
    print(f"[3/6] Enriched with {len(ti)} TI indicators, correlated into {len(incidents)} incidents")

    flagged = ai_summary.summarize(incidents, use_ai=args.ai)
    mode = "AI" if args.ai else "template"
    print(f"[4/6] Wrote {mode} summaries" + (f"; prompt-injection text flagged in {len(flagged)} incident(s)" if flagged else ""))

    scan, kev, epss = _vuln_paths(data)
    findings = vulns.prioritize(scan, kev, epss, live=args.live) if scan.exists() else []
    print(f"[5/6] Prioritized {len(findings)} vulnerability findings")

    store.save(out / "socpilot.db", events, incidents, findings)
    report.write_html(out / "report.html", incidents, findings, len(events), flagged, today)
    report.write_tickets(out / "tickets", incidents)
    report.write_json(out / "results.json", incidents, findings)
    print(f"[6/6] Outputs in {out}/: report.html, results.json, socpilot.db, tickets/")

    if args.webhook:
        sent = post_webhook(args.webhook, incidents)
        print(f"      Sent {sent} high/critical incident(s) to webhook")

    print("\nTop incidents:")
    for inc in incidents[:5]:
        print(f"  {inc.incident_id}  risk {inc.risk_score:>3}  {inc.severity:<8}  {inc.title}")
    # Non-zero exit when something critical is found, so CI / schedulers can page someone.
    return 2 if any(i.severity == "critical" for i in incidents) and args.fail_on_critical else 0


def post_webhook(url: str, incidents) -> int:
    """POST each high/critical incident as JSON, e.g. to an n8n / Tines / Slack workflow webhook."""
    sent = 0
    for inc in incidents:
        if inc.severity not in ("high", "critical"):
            continue
        body = json.dumps({
            "incident_id": inc.incident_id, "title": inc.title, "severity": inc.severity,
            "risk_score": inc.risk_score, "entities": inc.entities, "mitre": inc.mitre, "summary": inc.summary,
        }).encode()
        req = urllib.request.Request(url, data=body, method="POST", headers={"content-type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=15).close()
            sent += 1
        except Exception as exc:
            print(f"      webhook failed for {inc.incident_id}: {exc}")
    return sent


def cmd_vulns(args) -> int:
    scan, kev, epss = _vuln_paths(Path(args.data))
    findings = vulns.prioritize(scan, kev, epss, live=args.live)
    print(f"{'PRI':<4}{'SCORE':>6}  {'CVE':<16}{'HOST':<14}{'KEV':<5}{'EPSS':>6}  DUE")
    for f in findings:
        print(f"{f.priority:<4}{f.score:>6}  {f.cve:<16}{f.hostname:<14}{'yes' if f.in_kev else '':<5}{f.epss:>6.2f}  {f.due_date}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="socpilot", description="Automated detection, triage and vuln prioritization")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the full pipeline")
    r.add_argument("--data", default="data/sample")
    r.add_argument("--out", default="out")
    r.add_argument("--rules", default=str(detections.DEFAULT_RULES))
    r.add_argument("--year", type=int, default=2026, help="year for syslog lines (they omit it)")
    r.add_argument("--today", help="override today's date (YYYY-MM-DD) for SLA math")
    r.add_argument("--ai", action="store_true", help="LLM summaries via the Anthropic API")
    r.add_argument("--live", action="store_true", help="pull live CISA KEV + FIRST EPSS data")
    r.add_argument("--webhook", help="POST high/critical incidents to this URL (e.g. an n8n webhook)")
    r.add_argument("--fail-on-critical", action="store_true", help="exit code 2 if any critical incident")
    r.set_defaults(func=cmd_run)

    v = sub.add_parser("vulns", help="print the vulnerability remediation queue")
    v.add_argument("--data", default="data/sample")
    v.add_argument("--live", action="store_true")
    v.set_defaults(func=cmd_vulns)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

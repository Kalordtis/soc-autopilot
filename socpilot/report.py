"""Outputs: an HTML triage report, one Markdown ticket per incident, and JSON for other tools (SOAR, n8n)."""
from __future__ import annotations

import json
from collections import Counter
from datetime import date
from html import escape
from pathlib import Path

from .models import SEVERITY_ORDER, Incident
from .vulns import Finding

SEV_COLOR = {"critical": "#b42318", "high": "#c4320a", "medium": "#b54708", "low": "#475467"}
PRI_COLOR = {"P1": "#b42318", "P2": "#c4320a", "P3": "#b54708", "P4": "#475467"}


def _pill(text: str, color: str) -> str:
    return f'<span class="pill" style="--c:{color}">{escape(text)}</span>'


def write_html(path: Path, incidents: list[Incident], findings: list[Finding], n_events: int,
               flagged: dict[str, list[str]], today: date) -> None:
    n_alerts = sum(len(i.alerts) for i in incidents)
    sev_counts = Counter(i.severity for i in incidents)
    pri_counts = Counter(f.priority for f in findings)
    overdue = [f for f in findings if f.due_date and f.due_date < today]

    inc_html = []
    for inc in incidents:
        alerts_html = []
        for a in inc.alerts:
            ti = a.enrichment.get("threat_intel", [])
            ti_html = "".join(
                f"<li>{escape(h['ip'])}: {escape(h.get('tags', ''))} (confidence {escape(str(h.get('confidence')))}, {escape(h.get('source', ''))})</li>"
                for h in ti)
            alerts_html.append(f"""
            <details class="alert">
              <summary>{_pill(a.severity, SEV_COLOR[a.severity])} <b>{escape(a.rule_id)}</b> {escape(a.title)}
                <span class="muted">risk {a.risk_score} · {', '.join(escape(t) for t in a.mitre)}</span></summary>
              <p>{escape(a.description)}</p>
              <p class="muted">Score: {escape(' · '.join(a.enrichment.get('score_reasons', [])))}</p>
              {'<p><b>Threat intel</b></p><ul>' + ti_html + '</ul>' if ti_html else ''}
              <p><b>Playbook</b></p><ol>{''.join(f'<li>{escape(x)}</li>' for x in a.actions)}</ol>
              <p><b>Evidence</b></p><pre>{escape(chr(10).join(a.evidence))}</pre>
            </details>""")
        ents = inc.entities
        warn = ""
        if inc.incident_id in flagged:
            warn = (f'<p class="warn">Prompt-injection text found in log fields: '
                    f'{escape("; ".join(sorted(set(flagged[inc.incident_id]))))}. '
                    f'It was stripped before any AI processing.</p>')
        inc_html.append(f"""
        <section class="card">
          <div class="inc-head">
            <h3>{escape(inc.incident_id)} · {escape(inc.title)}</h3>
            <div>{_pill(inc.severity, SEV_COLOR[inc.severity])} <span class="risk">{inc.risk_score}</span></div>
          </div>
          <p class="muted">{inc.first_seen:%Y-%m-%d %H:%M} → {inc.last_seen:%Y-%m-%d %H:%M} UTC ·
             users: {escape(', '.join(ents.get('user', [])) or '–')} · IPs: {escape(', '.join(ents.get('ip', [])) or '–')}</p>
          <p>{escape(inc.summary)}</p>{warn}
          {''.join(alerts_html)}
        </section>""")

    vuln_rows = "".join(f"""
        <tr><td>{_pill(f.priority, PRI_COLOR[f.priority])}</td><td class="num">{f.score}</td>
        <td><b>{escape(f.cve)}</b><br><span class="muted">{escape(f.title)}</span></td>
        <td>{escape(f.hostname)}</td><td class="num">{f.cvss}</td><td class="num">{f.epss:.2f}</td>
        <td>{'Yes' if f.in_kev else ''}{' (ransomware)' if f.kev_ransomware else ''}</td>
        <td>{'Yes' if f.internet_facing else ''}</td>
        <td class="{'overdue' if f in overdue else ''}">{f.due_date}</td></tr>""" for f in findings)

    def stat(label, value, sub=""):
        return f'<div class="stat"><div class="v">{value}</div><div class="l">{label}</div><div class="s">{sub}</div></div>'

    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC Autopilot Report</title>
<style>
:root{{--bg:#f6f7f9;--card:#fff;--ink:#101828;--muted:#667085;--line:#e4e7ec}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0c111d;--card:#161b26;--ink:#f5f5f6;--muted:#94969c;--line:#333741}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}}
main{{max-width:1100px;margin:0 auto;padding:28px 16px 60px}}h1{{margin:0 0 4px;font-size:26px}}h2{{margin:36px 0 12px;font-size:19px}}
h3{{margin:0;font-size:16px}}.muted{{color:var(--muted);font-size:13px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:20px}}
.stat{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}}.stat .v{{font-size:28px;font-weight:700}}
.stat .l{{font-size:13px;font-weight:600}}.stat .s{{font-size:12px;color:var(--muted)}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:12px}}
.inc-head{{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap}}
.risk{{font-weight:700;font-size:20px;margin-left:6px}}
.pill{{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;color:var(--c);border:1px solid var(--c);text-transform:uppercase}}
details.alert{{border-top:1px solid var(--line);padding:8px 0}}summary{{cursor:pointer}}
pre{{background:var(--bg);padding:10px;border-radius:6px;overflow-x:auto;font-size:12px}}
.warn{{border-left:3px solid #b42318;padding:6px 10px;background:color-mix(in srgb,#b42318 8%,transparent)}}
.tablewrap{{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}
th{{font-size:12px;color:var(--muted)}}td.num{{text-align:right;font-variant-numeric:tabular-nums}}.overdue{{color:#b42318;font-weight:700}}
</style></head><body><main>
<h1>SOC Autopilot report</h1>
<div class="muted">Generated {today.isoformat()} · {n_events} events analyzed</div>
<div class="stats">
{stat('Incidents', len(incidents), ', '.join(f'{v} {k}' for k, v in sev_counts.most_common()))}
{stat('Alerts', n_alerts, 'correlated into incidents')}
{stat('Vulnerabilities', len(findings), ', '.join(f'{k}: {pri_counts[k]}' for k in ('P1','P2','P3','P4') if pri_counts[k]))}
{stat('Overdue fixes', len(overdue), 'past remediation SLA')}
</div>
<h2>Incidents (highest risk first)</h2>
{''.join(inc_html) or '<p>No incidents.</p>'}
<h2>Vulnerability remediation queue</h2>
<div class="tablewrap"><table><thead><tr><th>Priority</th><th>Score</th><th>CVE</th><th>Host</th><th>CVSS</th><th>EPSS</th><th>CISA KEV</th><th>Internet</th><th>Due</th></tr></thead>
<tbody>{vuln_rows}</tbody></table></div>
<p class="muted">Score = CVSS (30) + EPSS (25) + KEV (25, +5 ransomware) + internet-facing (10) + asset criticality (up to 7). KEV + internet-facing is always P1.</p>
</main></body></html>"""
    path.write_text(html, encoding="utf-8")


def write_tickets(out_dir: Path, incidents: list[Incident]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for inc in incidents:
        ents = inc.entities
        lines = [
            f"# {inc.incident_id}: {inc.title}", "",
            f"**Severity:** {inc.severity.upper()}  |  **Risk:** {inc.risk_score}/100  ",
            f"**Window:** {inc.first_seen:%Y-%m-%d %H:%M} to {inc.last_seen:%Y-%m-%d %H:%M} UTC  ",
            f"**MITRE ATT&CK:** {', '.join(inc.mitre)}", "",
            "## Summary", inc.summary, "",
            "## Entities",
            *[f"- **{k}:** {', '.join(v)}" for k, v in ents.items()], "",
            "## Response checklist",
        ]
        seen = []
        for a in sorted(inc.alerts, key=lambda a: -SEVERITY_ORDER[a.severity]):
            for act in a.actions:
                if act not in seen:
                    seen.append(act)
        lines += [f"- [ ] {x}" for x in seen] + ["", "## Alerts"]
        for a in inc.alerts:
            lines += [f"### {a.alert_id} {a.rule_id}: {a.title} ({a.severity}, risk {a.risk_score})",
                      a.description, "", "```", *a.evidence, "```", ""]
        (out_dir / f"{inc.incident_id}.md").write_text("\n".join(lines), encoding="utf-8")


def write_json(path: Path, incidents: list[Incident], findings: list[Finding]) -> None:
    data = {
        "incidents": [{
            "incident_id": i.incident_id, "title": i.title, "severity": i.severity, "risk_score": i.risk_score,
            "first_seen": i.first_seen.isoformat(), "last_seen": i.last_seen.isoformat(),
            "entities": i.entities, "mitre": i.mitre, "summary": i.summary,
            "alerts": [a.to_dict() for a in i.alerts],
        } for i in incidents],
        "vulnerabilities": [f.to_dict() for f in findings],
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")

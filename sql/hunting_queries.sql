-- Threat-hunting and reporting queries against out/socpilot.db
-- Run with:  sqlite3 out/socpilot.db < sql/hunting_queries.sql
-- (or open the DB in DB Browser for SQLite / the VS Code SQLite extension)

.headers on
.mode column

-- 1. Top external sources of failed logins (what to block first)
SELECT src_ip, COUNT(*) AS failures, COUNT(DISTINCT user) AS users_targeted,
       MIN(ts) AS first_seen, MAX(ts) AS last_seen
FROM events
WHERE event_type = 'auth_failure' AND src_ip NOT LIKE '10.%'
GROUP BY src_ip
ORDER BY failures DESC
LIMIT 10;

-- 2. Pivot: everything a suspicious IP did, across ALL log sources
SELECT ts, source, event_type, user, host
FROM events
WHERE src_ip = '203.0.113.45'
ORDER BY ts;

-- 3. Accounts that succeeded from an IP that also produced failures (possible compromise)
SELECT s.user, s.src_ip, s.ts AS success_at,
       (SELECT COUNT(*) FROM events f
         WHERE f.src_ip = s.src_ip AND f.event_type = 'auth_failure' AND f.ts < s.ts) AS prior_failures
FROM events s
WHERE s.event_type = 'auth_success'
  AND prior_failures >= 3
ORDER BY prior_failures DESC;

-- 4. Incident queue for the analyst on shift
SELECT incident_id, severity, risk_score, title, first_seen
FROM incidents
ORDER BY risk_score DESC;

-- 5. Which detections fire most (input for tuning / false-positive review)
SELECT rule_id, title, COUNT(*) AS alerts, ROUND(AVG(risk_score), 1) AS avg_risk
FROM alerts
GROUP BY rule_id, title
ORDER BY alerts DESC;

-- 6. Vulnerability SLA status: overdue P1/P2 fixes (swap the date for date('now') in real use)
SELECT priority, hostname, cve, score, due_date,
       julianday('2026-10-11') - julianday(due_date) AS days_overdue
FROM vulns
WHERE due_date < '2026-10-11'
ORDER BY priority, days_overdue DESC;

-- 7. Remediation workload per host (where one patch window fixes the most risk)
SELECT hostname, COUNT(*) AS findings, SUM(score) AS total_risk, MIN(priority) AS worst
FROM vulns
GROUP BY hostname
ORDER BY total_risk DESC;

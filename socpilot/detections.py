"""Detection engine. Rules live in rules.toml; this file holds the logic for each rule `type`."""
from __future__ import annotations

import math
import tomllib
from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path
from typing import Callable

from .models import Alert, Event

DEFAULT_RULES = Path(__file__).with_name("rules.toml")


def load_rules(path: str | Path = DEFAULT_RULES) -> tuple[dict, list[dict]]:
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
    return cfg.get("settings", {}), cfg.get("rule", [])


def _alert(rule: dict, events: list[Event], entities: dict[str, set], extra_desc: str = "") -> Alert:
    return Alert(
        rule_id=rule["id"], title=rule["title"], severity=rule["severity"], mitre=list(rule["mitre"]),
        first_seen=events[0].timestamp, last_seen=events[-1].timestamp,
        entities={k: sorted(v - {None}) for k, v in entities.items() if v - {None}},
        evidence=[e.summary() for e in events[:25]] + ([f"... {len(events) - 25} more events"] if len(events) > 25 else []),
        actions=list(rule.get("actions", [])),
        description=(rule.get("description", "") + (" " + extra_desc if extra_desc else "")).strip(),
    )


def _windowed_bursts(events: list[Event], window: timedelta, trigger: Callable[[deque], bool]) -> list[list[Event]]:
    """Slide a time window over (already sorted) events; return each maximal burst that
    satisfies `trigger`. Overlapping triggers merge into one burst so we alert once, not 40 times."""
    bursts: list[list[Event]] = []
    win: deque[Event] = deque()
    current: list[Event] | None = None
    seen: set[int] = set()
    for e in events:
        win.append(e)
        while win and e.timestamp - win[0].timestamp > window:
            win.popleft()
        if trigger(win):
            if current is None:
                current, seen = [], set()
            for x in win:
                if id(x) not in seen:
                    seen.add(id(x))
                    current.append(x)
        elif current is not None:
            bursts.append(current)
            current = None
    if current:
        bursts.append(current)
    return bursts


# ---------------------------------------------------------------- rule types

def detect_brute_force(events, rule, settings):
    window = timedelta(minutes=rule["window_minutes"])
    by_key = defaultdict(list)
    for e in events:
        if e.event_type == "auth_failure" and e.src_ip:
            by_key[(e.src_ip, e.user)].append(e)
    alerts = []
    for (ip, user), evs in by_key.items():
        for burst in _windowed_bursts(evs, window, lambda w: len(w) >= rule["threshold"]):
            alerts.append(_alert(rule, burst, {"ip": {ip}, "user": {user}, "host": {b.host for b in burst}},
                                 f"{len(burst)} failures against '{user}' from {ip}."))
    return alerts


def detect_password_spray(events, rule, settings):
    window = timedelta(minutes=rule["window_minutes"])
    by_ip = defaultdict(list)
    for e in events:
        if e.event_type == "auth_failure" and e.src_ip:
            by_ip[e.src_ip].append(e)
    alerts = []
    for ip, evs in by_ip.items():
        trig = lambda w: len({x.user for x in w}) >= rule["distinct_users"]
        for burst in _windowed_bursts(evs, window, trig):
            users = {b.user for b in burst}
            alerts.append(_alert(rule, burst, {"ip": {ip}, "user": users, "host": {b.host for b in burst}},
                                 f"{len(users)} distinct accounts targeted from {ip}."))
    return alerts


def detect_success_after_failures(events, rule, settings):
    window = timedelta(minutes=rule["window_minutes"])
    failures = defaultdict(list)
    alerts = []
    for e in events:
        if not e.src_ip:
            continue
        if e.event_type == "auth_failure":
            failures[e.src_ip].append(e)
        elif e.event_type == "auth_success":
            recent = [f for f in failures[e.src_ip] if e.timestamp - f.timestamp <= window]
            if len(recent) >= rule["min_failures"]:
                evs = recent + [e]
                alerts.append(_alert(rule, evs, {"ip": {e.src_ip}, "user": {e.user}, "host": {e.host}},
                                     f"{len(recent)} failures then success as '{e.user}' on {e.host}."))
                failures[e.src_ip].clear()
    return alerts


def detect_mfa_fatigue(events, rule, settings):
    window = timedelta(minutes=rule["window_minutes"])
    by_user = defaultdict(list)
    for e in events:
        if e.event_type in ("mfa_denied", "auth_success") and e.source == "cloud_signin" and e.user:
            by_user[e.user].append(e)
    alerts = []
    for user, evs in by_user.items():
        trig = lambda w: sum(x.event_type == "mfa_denied" for x in w) >= rule["min_denials"]
        for burst in _windowed_bursts(evs, window, trig):
            approved = any(b.event_type == "auth_success" for b in burst)
            a = _alert(rule, burst, {"user": {user}, "ip": {b.src_ip for b in burst}},
                       f"{sum(b.event_type == 'mfa_denied' for b in burst)} denied prompts"
                       + (" FOLLOWED BY AN APPROVAL." if approved else "."))
            if approved:
                a.severity = "critical"
            alerts.append(a)
    return alerts


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def detect_impossible_travel(events, rule, settings):
    last_seen: dict[str, Event] = {}
    alerts = []
    for e in events:
        if e.event_type != "auth_success" or e.lat is None or e.lon is None or not e.user:
            continue
        prev = last_seen.get(e.user)
        last_seen[e.user] = e
        if not prev:
            continue
        km = haversine_km(prev.lat, prev.lon, e.lat, e.lon)
        hours = max((e.timestamp - prev.timestamp).total_seconds() / 3600, 1 / 60)
        speed = km / hours
        if km >= rule["min_km"] and speed > rule["max_kmh"]:
            alerts.append(_alert(rule, [prev, e], {"user": {e.user}, "ip": {prev.src_ip, e.src_ip}},
                                 f"{prev.city}, {prev.country} -> {e.city}, {e.country}: "
                                 f"{km:,.0f} km in {hours * 60:.0f} min ({speed:,.0f} km/h)."))
    return alerts


def detect_new_privileged_account(events, rule, settings):
    window = timedelta(minutes=rule["window_minutes"])
    priv_groups = {g.lower() for g in settings.get("privileged_groups", [])}
    created: dict[str, Event] = {}
    alerts = []
    for e in events:
        if e.event_type == "user_created" and e.user:
            created[e.user.lower()] = e
        elif e.event_type == "group_member_added" and e.user:
            group = str(e.extra.get("group", "")).lower()
            c = created.get(e.user.lower())
            if group in priv_groups and c and e.timestamp - c.timestamp <= window:
                alerts.append(_alert(rule, [c, e], {"user": {e.user}, "host": {e.host},
                                                    "actor": {e.extra.get("added_by")}},
                                     f"'{e.user}' created and added to {e.extra.get('group')} "
                                     f"within {(e.timestamp - c.timestamp).seconds // 60} min."))
    return alerts


DETECTORS = {
    "brute_force": detect_brute_force,
    "password_spray": detect_password_spray,
    "success_after_failures": detect_success_after_failures,
    "mfa_fatigue": detect_mfa_fatigue,
    "impossible_travel": detect_impossible_travel,
    "new_privileged_account": detect_new_privileged_account,
}


def run_detections(events: list[Event], rules_path: str | Path = DEFAULT_RULES) -> list[Alert]:
    settings, rules = load_rules(rules_path)
    events = sorted(events, key=lambda e: e.timestamp)
    alerts: list[Alert] = []
    for rule in rules:
        fn = DETECTORS.get(rule["type"])
        if fn is None:
            raise ValueError(f"Unknown rule type {rule['type']!r} in rule {rule['id']}")
        alerts.extend(fn(events, rule, settings))
    for i, a in enumerate(sorted(alerts, key=lambda a: a.first_seen), 1):
        a.alert_id = f"ALR-{i:04d}"
    return sorted(alerts, key=lambda a: a.first_seen)

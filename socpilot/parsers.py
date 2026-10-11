"""Log parsers. Each one turns a vendor-specific format into normalized Events."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .models import Event

# ---------------------------------------------------------------- Linux (sshd)

_SYSLOG_PREFIX = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
_FAILED = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
_ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)")


def parse_linux_auth(path: str | Path, year: int | None = None) -> list[Event]:
    """Parse OpenSSH lines from /var/log/auth.log (syslog has no year, so pass one)."""
    year = year or datetime.now(timezone.utc).year
    events: list[Event] = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        m = _SYSLOG_PREFIX.match(line.strip())
        if not m:
            continue
        ts = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
        msg = m["msg"]
        if f := _FAILED.search(msg):
            etype, user, ip = "auth_failure", f["user"], f["ip"]
        elif a := _ACCEPTED.search(msg):
            etype, user, ip = "auth_success", a["user"], a["ip"]
        else:
            continue
        events.append(Event(ts, "linux_auth", etype, user=user, src_ip=ip, host=m["host"], raw=line))
    return events


# ------------------------------------------------------- Windows Security log

# Windows Security event IDs we care about
_WIN_MAP = {
    4624: "auth_success",          # An account was successfully logged on
    4625: "auth_failure",          # An account failed to log on
    4720: "user_created",          # A user account was created
    4732: "group_member_added",    # A member was added to a security-enabled local group
    4728: "group_member_added",    # ... global group
}


def _iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def parse_windows_events(path: str | Path) -> list[Event]:
    """Parse the JSON produced by scripts/Export-SecurityEvents.ps1."""
    events: list[Event] = []
    for rec in json.loads(Path(path).read_text(encoding="utf-8")):
        etype = _WIN_MAP.get(int(rec.get("EventID", 0)))
        if not etype:
            continue
        extra: dict = {"event_id": rec["EventID"]}
        if etype == "user_created":
            user = rec.get("TargetUserName")
            extra["created_by"] = rec.get("SubjectUserName")
        elif etype == "group_member_added":
            user = rec.get("MemberName") or rec.get("TargetUserName")
            extra["group"] = rec.get("TargetGroup")
            extra["added_by"] = rec.get("SubjectUserName")
        else:
            user = rec.get("TargetUserName")
            if rec.get("LogonType") is not None:
                extra["logon_type"] = rec["LogonType"]
            # WorkstationName is supplied by the *client* in NTLM auth, so it is attacker-controlled
            if rec.get("WorkstationName"):
                extra["workstation"] = rec["WorkstationName"]
        ip = rec.get("IpAddress")
        if ip in ("-", "", "::1", "127.0.0.1"):
            ip = None
        events.append(
            Event(_iso(rec["TimeCreated"]), "windows", etype, user=user, src_ip=ip,
                  host=rec.get("Computer"), raw=json.dumps(rec), extra=extra)
        )
    return events


# ------------------------------------------------- Cloud identity sign-ins

def parse_cloud_signins(path: str | Path) -> list[Event]:
    """Parse sign-in logs shaped like Microsoft Entra ID (Azure AD) sign-in exports."""
    events: list[Event] = []
    for rec in json.loads(Path(path).read_text(encoding="utf-8")):
        loc = rec.get("location") or {}
        geo = loc.get("geoCoordinates") or {}
        base = dict(
            timestamp=_iso(rec["createdDateTime"]), source="cloud_signin",
            user=rec.get("userPrincipalName"), src_ip=rec.get("ipAddress"),
            host=rec.get("appDisplayName"), country=loc.get("countryOrRegion"),
            city=loc.get("city"), lat=geo.get("latitude"), lon=geo.get("longitude"),
            raw=json.dumps(rec),
        )
        mfa = rec.get("mfaResult")
        if mfa == "denied":
            events.append(Event(event_type="mfa_denied", **base))
            continue
        ok = (rec.get("status") or {}).get("errorCode", 1) == 0
        etype = "auth_success" if ok else "auth_failure"
        extra = {"mfa": mfa} if mfa else {}
        events.append(Event(event_type=etype, extra=extra, **base))
    return events


def load_directory(data_dir: str | Path, year: int | None = None) -> list[Event]:
    """Load every supported log file found in a directory."""
    d = Path(data_dir)
    events: list[Event] = []
    if (p := d / "auth.log").exists():
        events += parse_linux_auth(p, year)
    if (p := d / "windows_events.json").exists():
        events += parse_windows_events(p)
    if (p := d / "signins.json").exists():
        events += parse_cloud_signins(p)
    return sorted(events, key=lambda e: e.timestamp)

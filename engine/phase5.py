"""Phase 5: offline, evidence-limited reporting. Never claims a validated bug."""
import json
import os
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from . import core

# No request/response bodies, tokens, URLs, hostnames or account data are exported.
_ALLOWED_STATES = {"pending", "approved", "validated", "not-reproducible", "skipped", "blocked"}

def _atomic_write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".phase5-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def snapshot(program):
    """Read local metadata only. User assertions never count as confirmed findings."""
    profile = core.load(program)
    if (core.BASE / "STOP").exists():
        raise PermissionError("Emergency STOP file present")
    with closing(core.db(program)) as conn:
        paused = core.getmeta(conn, "paused", "0") == "1"
        hosts = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        rows = conn.execute("SELECT status, COUNT(*) FROM suggestions GROUP BY status").fetchall()
        counts = {str(state): count for state, count in rows if state in _ALLOWED_STATES}
        audit = []
        present = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='local_audit'").fetchone()
        if present:
            audit = [dict(status=str(status), http_status=http_status, count=count)
                     for status, http_status, count in conn.execute(
                         "SELECT status,http_status,COUNT(*) FROM local_audit GROUP BY status,http_status ORDER BY status,http_status")]
    return {
        "schema_version": "phase5-report-1",
        "program": program,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "policy_reviewed": profile["policy_reviewed"],
        "paused": paused,
        "passive_host_count": hosts,
        "plan_status_counts": counts,
        "local_lab_observations": audit,
        "confirmed_vulnerabilities": [],
        "finding_confirmed": False,
        "evidence_classification": "unverified-observations-only",
        "limitations": [
            "No vulnerability is independently confirmed by this report.",
            "Plan status 'validated' is a user-entered assertion, not proof.",
            "HTTP 200 and missing security headers alone do not prove exploitability.",
            "Local lab observations are not evidence about external targets.",
            "No raw requests, responses, tokens, account identifiers, hostnames or URLs exported."
        ]
    }

def generate(program):
    data = snapshot(program)
    out = core.REPORTS / "phase5"
    json_path = out / (core.valid_name(program) + "-summary.json")
    md_path = out / (core.valid_name(program) + "-summary.md")
    markdown = [
        "# CyberPartha BOT v3 — Offline Research Summary", "",
        f"Program: `{data['program']}`", "",
        f"Generated (UTC): {data['generated_at']}", "",
        "## Research state", "",
        f"- Policy reviewed: {data['policy_reviewed']}",
        f"- Paused: {data['paused']}",
        f"- Passive host count (names omitted): {data['passive_host_count']}",
        "", "## Plan status counts (not vulnerability findings)", ""
    ]
    for state, count in sorted(data["plan_status_counts"].items()):
        markdown.append(f"- {state}: {count}")
    markdown += ["", "## Local lab observations (aggregated)", ""]
    for entry in data["local_lab_observations"]:
        markdown.append(f"- {entry['status']}, HTTP {entry['http_status']}: {entry['count']} record(s)")
    markdown += ["", "## Confirmed vulnerabilities", "", "None independently confirmed.", "", "## Limitations", ""]
    markdown += [f"- {line}" for line in data["limitations"]]
    markdown.append("")
    _atomic_write(json_path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    _atomic_write(md_path, "\n".join(markdown))
    return {"json": str(json_path), "markdown": str(md_path), "confirmed_findings": 0}

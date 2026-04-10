"""
alert_agent.py

Human review notification system — fires when triage routes a finding to
the human_review queue (Critical severity or needs_human_review flag).

Channels supported (configure via .env):
  - Slack   : SLACK_WEBHOOK_URL
  - Email   : SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, ALERT_EMAIL_TO
  - PagerDuty: PAGERDUTY_ROUTING_KEY  (Events API v2, Critical only)

All channels are attempted independently — a failure in one does not block others.
"""

import json
import os
import smtplib
import urllib.request
import urllib.error
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from dataclasses import dataclass

from triage_agent import TriageRecord


ALERT_LOG_DIR = Path(__file__).parent.parent / "reports" / "alerts"

PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

# Severity → PagerDuty severity mapping
PD_SEVERITY = {
    "Critical": "critical",
    "High": "error",
    "Medium": "warning",
    "Low": "info",
}

SLACK_COLORS = {
    "Critical": "#FF0000",
    "High": "#FF6600",
    "Medium": "#FFCC00",
    "Low": "#36A64F",
}


@dataclass
class AlertResult:
    finding_id: str
    slack_sent: bool = False
    email_sent: bool = False
    pagerduty_sent: bool = False
    errors: list = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []

    @property
    def any_sent(self) -> bool:
        return self.slack_sent or self.email_sent or self.pagerduty_sent


def _post_json(url: str, payload: dict, headers: dict = None) -> tuple[int, str]:
    """POST JSON to a URL. Returns (status_code, response_body)."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")
    except Exception as e:
        return 0, str(e)


def _send_slack(record: TriageRecord, commitment_hash: str) -> tuple[bool, str]:
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "")
    if not webhook_url:
        return False, "SLACK_WEBHOOK_URL not set"

    color = SLACK_COLORS.get(record.severity, "#888888")
    deadline = record.disclosure_deadline[:10]

    payload = {
        "text": f":rotating_light: *Glasswing Human Review Required* — {record.severity}",
        "attachments": [
            {
                "color": color,
                "fields": [
                    {"title": "Finding", "value": record.hack_title, "short": False},
                    {"title": "Repo", "value": record.repo, "short": True},
                    {"title": "File", "value": record.file, "short": True},
                    {"title": "Severity", "value": record.severity, "short": True},
                    {"title": "CVSS", "value": f"{record.cvss_score} ({record.cvss_vector})", "short": True},
                    {"title": "Route", "value": record.route, "short": True},
                    {"title": "Disclosure Deadline", "value": deadline, "short": True},
                    {"title": "Exploitation Path", "value": record.exploitation_path, "short": False},
                    {"title": "Population Impact", "value": record.population_impact, "short": True},
                    {"title": "SHA-3 Commitment", "value": f"`{commitment_hash}`", "short": False},
                    {"title": "Finding ID", "value": f"`{record.finding_id}`", "short": True},
                ],
                "footer": "Glasswing Remediation Pipeline",
                "ts": int(datetime.now(timezone.utc).timestamp()),
            }
        ],
    }

    status, body = _post_json(webhook_url, payload)
    if status == 200:
        return True, ""
    return False, f"Slack HTTP {status}: {body}"


def _send_email(record: TriageRecord, commitment_hash: str) -> tuple[bool, str]:
    host = os.environ.get("SMTP_HOST", "")
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER", "")
    password = os.environ.get("SMTP_PASS", "")
    to_addr = os.environ.get("ALERT_EMAIL_TO", "")

    if not all([host, user, password, to_addr]):
        return False, "SMTP config incomplete (SMTP_HOST, SMTP_USER, SMTP_PASS, ALERT_EMAIL_TO)"

    subject = f"[Glasswing] {record.severity} Finding — Human Review Required: {record.hack_title}"

    body_text = f"""
Glasswing Human Review Required
================================

Finding ID   : {record.finding_id}
Severity     : {record.severity}
CVSS Score   : {record.cvss_score} ({record.cvss_vector})
Vulnerability: {record.hack_title}
Repository   : {record.repo}
File         : {record.file}
Route        : {record.route}
Discovery    : {record.discovery_ts[:19]} UTC
Deadline     : {record.disclosure_deadline[:10]} (90-day disclosure policy)

Exploitation Path:
{record.exploitation_path}

Population Impact: {record.population_impact}

SHA-3 Commitment Hash:
{commitment_hash}

Notes:
{record.notes[:500]}

---
Action required: review the triage record at reports/triage/{record.finding_id}.json
and approve or reject the auto-fix recommendation before the disclosure deadline.
"""

    body_html = f"""
<html><body>
<h2 style="color: {'#cc0000' if record.severity == 'Critical' else '#ff6600'}">
  Glasswing — Human Review Required
</h2>
<table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse">
  <tr><th>Finding ID</th><td><code>{record.finding_id}</code></td></tr>
  <tr><th>Severity</th><td><strong>{record.severity}</strong></td></tr>
  <tr><th>CVSS</th><td>{record.cvss_score} ({record.cvss_vector})</td></tr>
  <tr><th>Vulnerability</th><td>{record.hack_title}</td></tr>
  <tr><th>Repository</th><td>{record.repo}</td></tr>
  <tr><th>File</th><td>{record.file}</td></tr>
  <tr><th>Route</th><td>{record.route}</td></tr>
  <tr><th>Discovery</th><td>{record.discovery_ts[:19]} UTC</td></tr>
  <tr><th>Deadline</th><td>{record.disclosure_deadline[:10]}</td></tr>
  <tr><th>Exploitation Path</th><td>{record.exploitation_path}</td></tr>
  <tr><th>Population Impact</th><td>{record.population_impact}</td></tr>
  <tr><th>SHA-3 Commitment</th><td><code>{commitment_hash}</code></td></tr>
</table>
<p><strong>Notes:</strong><br>{record.notes[:500]}</p>
<hr>
<p>Review: <code>reports/triage/{record.finding_id}.json</code></p>
</body></html>
"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = to_addr
    msg.attach(MIMEText(body_text, "plain"))
    msg.attach(MIMEText(body_html, "html"))

    try:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.starttls()
            server.login(user, password)
            server.sendmail(user, [to_addr], msg.as_string())
        return True, ""
    except Exception as e:
        return False, str(e)


def _send_pagerduty(record: TriageRecord, commitment_hash: str) -> tuple[bool, str]:
    routing_key = os.environ.get("PAGERDUTY_ROUTING_KEY", "")
    if not routing_key:
        return False, "PAGERDUTY_ROUTING_KEY not set"

    # Only page for Critical — High gets Slack/email only
    if record.severity not in ("Critical", "High"):
        return False, "PagerDuty skipped — severity below threshold"

    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": f"glasswing-{record.finding_id}",
        "payload": {
            "summary": f"[{record.severity}] {record.hack_title} in {record.repo}",
            "severity": PD_SEVERITY.get(record.severity, "error"),
            "source": "glasswing-pipeline",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "custom_details": {
                "finding_id": record.finding_id,
                "repo": record.repo,
                "file": record.file,
                "cvss_score": record.cvss_score,
                "cvss_vector": record.cvss_vector,
                "exploitation_path": record.exploitation_path,
                "disclosure_deadline": record.disclosure_deadline[:10],
                "commitment_hash": commitment_hash,
            },
        },
    }

    status, body = _post_json(PAGERDUTY_EVENTS_URL, payload)
    if status in (200, 202):
        return True, ""
    return False, f"PagerDuty HTTP {status}: {body}"


def _log_alert(record: TriageRecord, result: AlertResult):
    ALERT_LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = ALERT_LOG_DIR / f"{record.finding_id}_alert.json"
    log_path.write_text(json.dumps({
        "finding_id": record.finding_id,
        "hack_title": record.hack_title,
        "severity": record.severity,
        "repo": record.repo,
        "alerted_at": datetime.now(timezone.utc).isoformat(),
        "slack_sent": result.slack_sent,
        "email_sent": result.email_sent,
        "pagerduty_sent": result.pagerduty_sent,
        "errors": result.errors,
    }, indent=2))


def fire_alert(record: TriageRecord, commitment_hash: str = "") -> AlertResult:
    """
    Fire human review alerts for a triage record across all configured channels.
    All channels are attempted independently — one failure does not block others.
    """
    result = AlertResult(finding_id=record.finding_id)

    print(f"  [alert] Firing human review alert for {record.finding_id} "
          f"({record.severity}) via configured channels...")

    # Slack
    ok, err = _send_slack(record, commitment_hash)
    result.slack_sent = ok
    if ok:
        print(f"  [alert] Slack ✓")
    elif err:
        result.errors.append(f"slack: {err}")
        print(f"  [alert] Slack skipped: {err}")

    # Email
    ok, err = _send_email(record, commitment_hash)
    result.email_sent = ok
    if ok:
        print(f"  [alert] Email ✓")
    elif err:
        result.errors.append(f"email: {err}")
        print(f"  [alert] Email skipped: {err}")

    # PagerDuty (Critical + High only)
    ok, err = _send_pagerduty(record, commitment_hash)
    result.pagerduty_sent = ok
    if ok:
        print(f"  [alert] PagerDuty ✓")
    elif err:
        result.errors.append(f"pagerduty: {err}")
        if "skipped" not in err:
            print(f"  [alert] PagerDuty skipped: {err}")

    if not result.any_sent:
        print(f"  [alert] WARNING: No channels delivered. Configure SLACK_WEBHOOK_URL, "
              f"SMTP_*, or PAGERDUTY_ROUTING_KEY in .env")

    _log_alert(record, result)
    return result


def fire_alerts_for_queue(human_queue: list, commitment_hashes: dict = None) -> list[AlertResult]:
    """
    Fire alerts for all findings in the human_review queue.

    human_queue: list of (finding, TriageRecord) tuples from triage_agent
    commitment_hashes: {finding_id: hash} — optional, computed if not provided
    """
    import hashlib

    results = []
    commitment_hashes = commitment_hashes or {}

    for finding, record in human_queue:
        # Reproduce commitment hash if not provided
        if record.finding_id not in commitment_hashes:
            raw = f"{record.finding_id}|{record.repo}|{record.file}|{record.discovery_ts}"
            commitment_hashes[record.finding_id] = hashlib.sha3_256(raw.encode()).hexdigest()

        result = fire_alert(record, commitment_hashes[record.finding_id])
        results.append(result)

    return results


if __name__ == "__main__":
    # Smoke test — prints what would be sent without requiring live credentials
    import sys
    from triage_agent import TriageRecord
    from datetime import timedelta

    now = datetime.now(timezone.utc).isoformat()
    test_record = TriageRecord(
        finding_id="test0001deadbeef",
        hack_id="test-deserialization",
        hack_title="Java Unsafe Deserialization → RCE",
        repo="stacksry/backend-service",
        file="src/main/java/com/example/Server.java",
        severity="Critical",
        cvss_score=9.8,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        route="human_review",
        discovery_ts=now,
        disclosure_deadline=(datetime.now(timezone.utc) + timedelta(days=90)).isoformat(),
        exploitation_path="Unauthenticated attacker sends crafted serialized object to TCP port 8080",
        population_impact="broad",
        notes="ObjectInputStream.readObject() called with no filter on incoming network data.",
    )

    print("Glasswing Alert Agent — smoke test")
    print("Configured channels:")
    print(f"  Slack     : {'✓' if os.environ.get('SLACK_WEBHOOK_URL') else '✗ (SLACK_WEBHOOK_URL not set)'}")
    print(f"  Email     : {'✓' if os.environ.get('SMTP_HOST') else '✗ (SMTP_HOST not set)'}")
    print(f"  PagerDuty : {'✓' if os.environ.get('PAGERDUTY_ROUTING_KEY') else '✗ (PAGERDUTY_ROUTING_KEY not set)'}")
    print()

    result = fire_alert(test_record, "abc123def456" * 4)
    print(f"\nResult: slack={result.slack_sent} email={result.email_sent} pd={result.pagerduty_sent}")
    if result.errors:
        for e in result.errors:
            print(f"  Error: {e}")

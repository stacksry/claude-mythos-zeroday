"""
disclosure_agent.py

Responsible disclosure lifecycle manager — mirrors Anthropic's approach
from the Mythos Preview blog:

  - SHA-3 commitment hash at time of discovery
  - 90-day countdown per finding
  - Vendor notification drafts (CVE-ready format)
  - 45-day escalation if no vendor response
  - Public disclosure brief generated on day 90

Run periodically (daily) to check timelines and generate notifications.
"""

import json
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from dataclasses import asdict
import anthropic
from triage_agent import TriageRecord, load_open_records, TRIAGE_DIR


MODEL = "claude-opus-4-6"
DISCLOSURE_DIR = Path(__file__).parent.parent / "reports" / "disclosure"

VENDOR_NOTIFY_DAY = 1     # Send vendor notification on day 1 (immediate)
ESCALATION_DAY   = 45     # Escalate if no response by day 45
DISCLOSURE_DAY   = 90     # Public disclosure on day 90


def _days_since(ts: str) -> int:
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days


def _commitment_hash(record: TriageRecord) -> str:
    """Reproduce the SHA-3 commitment hash for a finding."""
    raw = f"{record.finding_id}|{record.repo}|{record.file}|{record.discovery_ts}"
    return hashlib.sha3_256(raw.encode()).hexdigest()


def generate_vendor_notification(record: TriageRecord) -> str:
    """Generate a CVE-ready vendor notification for a finding."""
    client = anthropic.Anthropic()
    prompt = (
        f"Write a professional responsible disclosure notification to the vendor/maintainer.\n\n"
        f"Finding ID: {record.finding_id}\n"
        f"Commitment hash (SHA-3): {_commitment_hash(record)}\n"
        f"Repository: {record.repo}\n"
        f"Affected file: {record.file}\n"
        f"Vulnerability: {record.hack_title}\n"
        f"Severity: {record.severity}\n"
        f"CVSS Score: {record.cvss_score} ({record.cvss_vector})\n"
        f"Affected library: {record.affected_library or 'N/A'}\n"
        f"Discovery date: {record.discovery_ts[:10]}\n"
        f"Disclosure deadline: {record.disclosure_deadline[:10]} (90 days)\n"
        f"Exploitation path: {record.exploitation_path}\n"
        f"Population impact: {record.population_impact}\n\n"
        "Format:\n"
        "1. Subject line\n"
        "2. Severity and CVSS\n"
        "3. Description (2-3 sentences)\n"
        "4. Reproduction steps (brief)\n"
        "5. Recommended fix\n"
        "6. Timeline (90-day disclosure policy)\n"
        "7. SHA-3 commitment hash for proof of prior discovery\n"
        "Be professional, technical, and concise."
    )
    response = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    for block in response.content:
        if block.type == "text":
            return block.text.strip()
    return ""


def generate_public_disclosure(record: TriageRecord) -> str:
    """Generate a public disclosure brief for day-90 release."""
    client = anthropic.Anthropic()
    prompt = (
        f"Write a public security disclosure brief for the following finding.\n\n"
        f"Vulnerability: {record.hack_title}\n"
        f"Repository: {record.repo}\n"
        f"CVSS: {record.cvss_score} ({record.severity})\n"
        f"Discovery date: {record.discovery_ts[:10]}\n"
        f"Patched: {record.status == 'fixed'}\n"
        f"SHA-3 commitment: {_commitment_hash(record)}\n"
        f"Notes: {record.notes[:300]}\n\n"
        "Format: title, TL;DR (2 sentences), technical details, timeline, "
        "patch status, SHA-3 commitment hash, credit."
    )
    response = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    for block in response.content:
        if block.type == "text":
            return block.text.strip()
    return ""


def _save_disclosure_doc(finding_id: str, doc_type: str, content: str):
    DISCLOSURE_DIR.mkdir(parents=True, exist_ok=True)
    path = DISCLOSURE_DIR / f"{finding_id}_{doc_type}.md"
    path.write_text(content)
    print(f"  [disclosure] Saved: {path.name}")


def run_disclosure_cycle() -> dict:
    """
    Check all open triage records and take appropriate disclosure actions.
    Returns summary of actions taken.
    """
    records = load_open_records()
    actions = {
        "vendor_notifications": [],
        "escalations": [],
        "public_disclosures": [],
        "no_action": [],
    }

    print(f"[disclosure] Checking {len(records)} open findings...")

    for record in records:
        days = _days_since(record.discovery_ts)
        commitment = _commitment_hash(record)

        print(f"  [{days:3d}d] {record.finding_id} — {record.hack_title} "
              f"({record.severity}) in {record.repo}")

        # Day 1: Send vendor notification
        notification_path = DISCLOSURE_DIR / f"{record.finding_id}_vendor_notification.md"
        if days >= VENDOR_NOTIFY_DAY and not notification_path.exists():
            print(f"         → Generating vendor notification...")
            note = generate_vendor_notification(record)
            _save_disclosure_doc(record.finding_id, "vendor_notification", note)
            actions["vendor_notifications"].append({
                "finding_id": record.finding_id,
                "repo": record.repo,
                "severity": record.severity,
                "commitment_hash": commitment,
            })

        # Day 45: Escalation if not fixed
        escalation_path = DISCLOSURE_DIR / f"{record.finding_id}_escalation.md"
        if days >= ESCALATION_DAY and record.status != "fixed" and not escalation_path.exists():
            print(f"         → Day {days}: Generating escalation notice...")
            escalation = (
                f"# Escalation Notice — Day {days}\n\n"
                f"**Finding:** {record.hack_title}\n"
                f"**Repo:** {record.repo}\n"
                f"**CVSS:** {record.cvss_score} ({record.severity})\n"
                f"**Discovery:** {record.discovery_ts[:10]}\n"
                f"**Deadline:** {record.disclosure_deadline[:10]}\n"
                f"**Status:** {record.status}\n"
                f"**SHA-3 Commitment:** `{commitment}`\n\n"
                f"This finding has not been patched after {days} days. "
                f"Public disclosure will proceed on day {DISCLOSURE_DAY} "
                f"({record.disclosure_deadline[:10]}) regardless of patch status.\n"
            )
            _save_disclosure_doc(record.finding_id, "escalation", escalation)
            actions["escalations"].append({
                "finding_id": record.finding_id,
                "repo": record.repo,
                "days_open": days,
            })

        # Day 90: Public disclosure
        public_path = DISCLOSURE_DIR / f"{record.finding_id}_public_disclosure.md"
        if days >= DISCLOSURE_DAY and not public_path.exists():
            print(f"         → Day {days}: Generating public disclosure brief...")
            brief = generate_public_disclosure(record)
            _save_disclosure_doc(record.finding_id, "public_disclosure", brief)
            # Update triage record status
            record_path = TRIAGE_DIR / f"{record.finding_id}.json"
            if record_path.exists():
                data = json.loads(record_path.read_text())
                data["status"] = "disclosed"
                record_path.write_text(json.dumps(data, indent=2))
            actions["public_disclosures"].append({
                "finding_id": record.finding_id,
                "repo": record.repo,
                "patched": record.status == "fixed",
                "commitment_hash": commitment,
            })

        else:
            days_remaining = DISCLOSURE_DAY - days
            actions["no_action"].append({
                "finding_id": record.finding_id,
                "days_open": days,
                "days_remaining": days_remaining,
            })

    return actions


if __name__ == "__main__":
    print("Running disclosure cycle...")
    summary = run_disclosure_cycle()
    print("\nSummary:")
    print(f"  Vendor notifications sent : {len(summary['vendor_notifications'])}")
    print(f"  Escalations generated     : {len(summary['escalations'])}")
    print(f"  Public disclosures        : {len(summary['public_disclosures'])}")
    print(f"  No action needed          : {len(summary['no_action'])}")

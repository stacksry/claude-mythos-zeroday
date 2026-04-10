"""
mcp_server.py

MCP (Model Context Protocol) server — exposes the Glasswing pipeline as
tools that VS Code Copilot agent mode can invoke directly from chat.

The existing Anthropic API agents are unchanged. This is a thin wrapper
that translates MCP tool calls into orchestrator/agent invocations.

Usage (automatic via .vscode/mcp.json):
    python agents/mcp_server.py

Manual test:
    echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | python agents/mcp_server.py

Tools exposed to Copilot:
  glasswing_scan_org          Full pipeline: scan → validate → triage → fix → test → report
  glasswing_dry_run           Scan only — no PRs opened
  glasswing_disclosure_status Check all open findings and 90-day disclosure timelines
  glasswing_list_findings     List open triage records with CVSS + severity
  glasswing_get_finding       Get a specific triage record by finding_id
  glasswing_get_report        Return the latest remediation report
  glasswing_alert_test        Smoke-test alert channels (Slack/email/PagerDuty)
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from datetime import datetime, timezone

# ── Path setup — agents/ must be on sys.path ──────────────────────────────────
AGENTS_DIR = Path(__file__).parent
REPO_ROOT = AGENTS_DIR.parent
sys.path.insert(0, str(AGENTS_DIR))

from dotenv import load_dotenv
load_dotenv(AGENTS_DIR / ".env")

from mcp.server.fastmcp import FastMCP

# ── MCP server ────────────────────────────────────────────────────────────────

mcp = FastMCP(
    "glasswing",
    instructions=(
        "Glasswing is an automated vulnerability remediation pipeline for GitHub organizations. "
        "It scans repos for zero-day vulnerabilities, validates findings, triages by CVSS severity, "
        "applies fixes via PRs, and manages 90-day responsible disclosure timelines. "
        "Use glasswing_dry_run first to see what would be found before opening any PRs."
    ),
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _check_env() -> str | None:
    """Return an error string if required env vars are missing, else None."""
    missing = [v for v in ["ANTHROPIC_API_KEY", "GITHUB_TOKEN"] if not os.environ.get(v)]
    if missing:
        return f"Missing required environment variables: {', '.join(missing)}. Add them to agents/.env"
    return None


def _latest_report() -> Path | None:
    report_dir = REPO_ROOT / "reports"
    reports = sorted(report_dir.glob("remediation_*.md"), reverse=True)
    return reports[0] if reports else None


def _format_triage_record(data: dict) -> str:
    return (
        f"**{data.get('finding_id', 'unknown')}**\n"
        f"- Vulnerability : {data.get('hack_title')}\n"
        f"- Repo         : {data.get('repo')}\n"
        f"- File         : {data.get('file')}\n"
        f"- Severity     : {data.get('severity')} (CVSS {data.get('cvss_score')})\n"
        f"- Route        : {data.get('route')}\n"
        f"- Status       : {data.get('status')}\n"
        f"- Deadline     : {str(data.get('disclosure_deadline', ''))[:10]}\n"
        f"- Exploitation : {data.get('exploitation_path')}\n"
        f"- Impact       : {data.get('population_impact')}\n"
    )


# ── Tools ─────────────────────────────────────────────────────────────────────

@mcp.tool()
async def glasswing_scan_org(
    org: str,
    hack_filter: str = "",
    workers: int = 4,
) -> str:
    """
    Run the full Glasswing pipeline against a GitHub organization.

    Scans all repos → validates findings → triages by CVSS → opens fix PRs
    → asserts fixes → generates remediation report.

    Args:
        org: GitHub organization name (e.g. 'my-company')
        hack_filter: Optional hack ID substring to run only one vulnerability class
                     (e.g. 'deserialization', 'oob', 'sql_injection')
        workers: Number of parallel workers (default 4, increase for large orgs)

    Returns:
        Path to the generated remediation report and a summary of actions taken.

    WARNING: This opens real PRs. Use glasswing_dry_run first.
    """
    err = _check_env()
    if err:
        return f"ERROR: {err}"

    try:
        from orchestrator import _run_pipeline_async
        report_path = await _run_pipeline_async(
            org=org,
            hack_filter=hack_filter or None,
            dry_run=False,
            workers=workers,
        )
        content = report_path.read_text()[:4000]
        return f"Pipeline complete. Report saved to: {report_path}\n\n---\n\n{content}"
    except Exception as exc:
        return f"Pipeline error: {exc}"


@mcp.tool()
async def glasswing_dry_run(
    org: str,
    hack_filter: str = "",
    workers: int = 4,
) -> str:
    """
    Scan a GitHub org for vulnerabilities WITHOUT opening any PRs.

    Runs the full discovery pipeline (ranker → scanner → supply_chain →
    validator → sandbox → triage) and reports what would be fixed.

    Args:
        org: GitHub organization name (e.g. 'stacksry')
        hack_filter: Optional vulnerability class filter (e.g. 'deserialization')
        workers: Parallel workers (default 4)

    Returns:
        Summary of findings with severity, repo, file, and CVSS scores.
    """
    err = _check_env()
    if err:
        return f"ERROR: {err}"

    try:
        from orchestrator import _run_pipeline_async
        report_path = await _run_pipeline_async(
            org=org,
            hack_filter=hack_filter or None,
            dry_run=True,
            workers=workers,
        )
        content = report_path.read_text()[:4000]
        return f"Dry run complete. Report: {report_path}\n\n---\n\n{content}"
    except Exception as exc:
        return f"Dry run error: {exc}"


@mcp.tool()
async def glasswing_disclosure_status() -> str:
    """
    Check the 90-day responsible disclosure timeline for all open findings.

    Shows:
    - Days since discovery
    - Days until public disclosure deadline
    - Whether vendor notification has been sent (day 1)
    - Whether escalation notice is due (day 45)
    - Whether public disclosure brief is due (day 90)

    Returns a table of all open findings sorted by urgency.
    """
    err = _check_env()
    if err:
        return f"ERROR: {err}"

    try:
        from disclosure_agent import run_disclosure_cycle
        loop = asyncio.get_event_loop()
        summary = await loop.run_in_executor(None, run_disclosure_cycle)

        lines = ["## Glasswing Disclosure Status\n"]

        if summary["public_disclosures"]:
            lines.append(f"### Day 90 — Public Disclosure Generated ({len(summary['public_disclosures'])})")
            for item in summary["public_disclosures"]:
                lines.append(f"- `{item['finding_id']}` {item['repo']} (patched={item['patched']})")
            lines.append("")

        if summary["escalations"]:
            lines.append(f"### Day 45 — Escalation Notices Sent ({len(summary['escalations'])})")
            for item in summary["escalations"]:
                lines.append(f"- `{item['finding_id']}` {item['repo']} — {item['days_open']}d open")
            lines.append("")

        if summary["vendor_notifications"]:
            lines.append(f"### Day 1 — Vendor Notifications Sent ({len(summary['vendor_notifications'])})")
            for item in summary["vendor_notifications"]:
                lines.append(f"- `{item['finding_id']}` {item['repo']} ({item['severity']})")
            lines.append("")

        if summary["no_action"]:
            lines.append(f"### No Action Needed ({len(summary['no_action'])} findings)")
            for item in sorted(summary["no_action"], key=lambda x: x["days_remaining"]):
                lines.append(
                    f"- `{item['finding_id']}` — {item['days_open']}d open, "
                    f"{item['days_remaining']}d until disclosure"
                )

        return "\n".join(lines)
    except Exception as exc:
        return f"Disclosure cycle error: {exc}"


@mcp.tool()
async def glasswing_list_findings(
    status: str = "open",
    severity: str = "",
) -> str:
    """
    List triage records from the Glasswing pipeline.

    Args:
        status: Filter by status — 'open', 'fixed', 'disclosed', or 'all' (default: 'open')
        severity: Optional severity filter — 'Critical', 'High', 'Medium', 'Low'

    Returns:
        Table of findings with ID, severity, CVSS, repo, status, and deadline.
    """
    triage_dir = REPO_ROOT / "reports" / "triage"
    if not triage_dir.exists():
        return "No triage records found. Run glasswing_dry_run first."

    records = []
    for f in sorted(triage_dir.glob("*.json")):
        try:
            data = json.loads(f.read_text())
            records.append(data)
        except Exception:
            continue

    # Filter
    if status != "all":
        records = [r for r in records if r.get("status") == status]
    if severity:
        records = [r for r in records if r.get("severity", "").lower() == severity.lower()]

    if not records:
        return f"No findings match status='{status}'" + (f" severity='{severity}'" if severity else "")

    # Sort by CVSS descending
    records.sort(key=lambda r: r.get("cvss_score", 0), reverse=True)

    lines = [f"## Open Findings ({len(records)} total)\n"]
    now = datetime.now(timezone.utc)

    for r in records:
        deadline_str = str(r.get("disclosure_deadline", ""))[:10]
        try:
            from disclosure_agent import _days_since
            days_open = _days_since(r["discovery_ts"])
            days_left = 90 - days_open
        except Exception:
            days_open = "?"
            days_left = "?"

        lines.append(
            f"- **{r.get('finding_id', '?')[:12]}** "
            f"[{r.get('severity')} CVSS {r.get('cvss_score')}] "
            f"`{r.get('repo')}/{r.get('file')}` — "
            f"{days_open}d open, {days_left}d to disclosure"
        )

    return "\n".join(lines)


@mcp.tool()
async def glasswing_get_finding(finding_id: str) -> str:
    """
    Get the full triage record for a specific finding.

    Args:
        finding_id: The finding ID (full or prefix, e.g. 'abc123def456')

    Returns:
        Full triage record including CVSS vector, exploitation path, SHA-3 commitment,
        disclosure timeline, and current status.
    """
    triage_dir = REPO_ROOT / "reports" / "triage"
    if not triage_dir.exists():
        return "No triage records found."

    # Match by prefix or full ID
    matches = [
        f for f in triage_dir.glob("*.json")
        if f.stem.startswith(finding_id) or finding_id.startswith(f.stem)
    ]

    if not matches:
        return f"No finding found matching ID '{finding_id}'."
    if len(matches) > 1:
        ids = [f.stem for f in matches]
        return f"Multiple matches: {ids}. Provide a more specific ID."

    try:
        data = json.loads(matches[0].read_text())
    except Exception as exc:
        return f"Error reading record: {exc}"

    # Also check if disclosure docs exist
    disclosure_dir = REPO_ROOT / "reports" / "disclosure"
    docs = []
    if disclosure_dir.exists():
        for doc_type in ("vendor_notification", "escalation", "public_disclosure"):
            path = disclosure_dir / f"{data['finding_id']}_{doc_type}.md"
            if path.exists():
                docs.append(doc_type)

    result = _format_triage_record(data)
    if docs:
        result += f"\n**Disclosure docs generated:** {', '.join(docs)}\n"

    # Include notes (truncated)
    if data.get("notes"):
        result += f"\n**Validator notes:**\n{data['notes'][:500]}\n"

    return result


@mcp.tool()
async def glasswing_get_report() -> str:
    """
    Return the content of the latest remediation report.

    Returns:
        Full markdown report including hygiene score, status table,
        per-hack breakdown, and action items.
    """
    report = _latest_report()
    if not report:
        return "No remediation report found. Run glasswing_scan_org or glasswing_dry_run first."

    content = report.read_text()
    if len(content) > 6000:
        return content[:6000] + f"\n\n... (truncated — full report at {report})"
    return content


@mcp.tool()
async def glasswing_correct_cvss(
    finding_id: str,
    corrected_score: float,
    corrected_vector: str,
    reason: str,
) -> str:
    """
    Override the CVSS score for a finding and record the correction for future calibration.

    This is the human feedback mechanism — when a triage agent gets the severity wrong,
    call this tool to correct it. The correction is stored in memory and used to calibrate
    future CVSS scoring for the same vulnerability class.

    Args:
        finding_id: The finding ID to correct (full or prefix)
        corrected_score: The correct CVSS base score (0.0–10.0)
        corrected_vector: The correct CVSS v3.1 vector string
        reason: Why the original score was wrong (used as future calibration context)

    Returns:
        Confirmation of correction applied and stored.
    """
    triage_dir = REPO_ROOT / "reports" / "triage"
    matches = [f for f in triage_dir.glob("*.json") if f.stem.startswith(finding_id)]

    if not matches:
        return f"No finding found matching ID '{finding_id}'."

    try:
        data = json.loads(matches[0].read_text())
    except Exception as exc:
        return f"Error reading record: {exc}"

    original_score = data.get("cvss_score", 0.0)
    original_vector = data.get("cvss_vector", "")
    hack_id = data.get("hack_id", "")

    # Update the triage record on disk
    data["cvss_score"] = corrected_score
    data["cvss_vector"] = corrected_vector
    matches[0].write_text(json.dumps(data, indent=2))

    # Write to memory for future calibration
    import memory_agent as mem
    mem.record_cvss_correction(
        hack_id=hack_id,
        original_score=original_score,
        corrected_score=corrected_score,
        original_vector=original_vector,
        corrected_vector=corrected_vector,
        reason=reason,
    )

    return (
        f"CVSS corrected for `{data['finding_id']}`:\n"
        f"- Was   : {original_score} ({original_vector})\n"
        f"- Now   : {corrected_score} ({corrected_vector})\n"
        f"- Reason: {reason}\n\n"
        f"Correction stored in memory — future `{hack_id}` triage will use this calibration."
    )


@mcp.tool()
async def glasswing_memory_stats() -> str:
    """
    Show what the pipeline has learned so far across all feedback loops.

    Returns a summary of stored memory: fix patterns, false positive signals,
    CVSS corrections, ranker calibrations, and confirmed scan patterns.
    """
    import memory_agent as mem
    stats = mem.get_store().stats()
    lines = ["## Glasswing Memory Store\n"]
    total = sum(stats.values())
    for key, count in stats.items():
        label = key.replace("_", " ").title()
        lines.append(f"- {label:<30} {count} record(s)")
    lines.append(f"\n**Total:** {total} records across {len(stats)} feedback loops")
    if total == 0:
        lines.append("\nNo memory yet — run the pipeline to start learning.")
    else:
        lines.append(f"\nMemory location: `{mem.MEMORY_DIR}`")
    return "\n".join(lines)


@mcp.tool()
async def glasswing_alert_test() -> str:
    """
    Smoke-test the alert channels (Slack, email, PagerDuty) with a fake Critical finding.

    Does NOT send real findings — uses a test record to verify channel configuration.
    Safe to run at any time to confirm your .env alert settings are working.

    Returns:
        Status of each channel: which sent, which are not configured, any errors.
    """
    err = _check_env()
    if err:
        return f"ERROR: {err}"

    try:
        import alert_agent
        from triage_agent import TriageRecord
        from datetime import timedelta

        now = datetime.now(timezone.utc).isoformat()
        test_record = TriageRecord(
            finding_id="test0000deadbeef",
            hack_id="mcp-alert-test",
            hack_title="[TEST] Glasswing MCP alert channel verification",
            repo="stacksry/test-repo",
            file="src/test/AlertTest.java",
            severity="Critical",
            cvss_score=9.8,
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            route="human_review",
            discovery_ts=now,
            disclosure_deadline=(
                datetime.now(timezone.utc) + timedelta(days=90)
            ).isoformat(),
            exploitation_path="This is a test alert from the Glasswing MCP server.",
            population_impact="narrow",
            notes="Test alert triggered via glasswing_alert_test MCP tool.",
        )

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None, alert_agent.fire_alert, test_record, "test" * 16
        )

        lines = ["## Alert Channel Test Results\n"]
        lines.append(f"- Slack      : {'✓ sent' if result.slack_sent else '✗ not sent'}")
        lines.append(f"- Email      : {'✓ sent' if result.email_sent else '✗ not sent'}")
        lines.append(f"- PagerDuty  : {'✓ sent' if result.pagerduty_sent else '✗ not sent'}")

        if result.errors:
            lines.append("\n**Errors / not configured:**")
            for e in result.errors:
                lines.append(f"  - {e}")

        lines.append("\nConfigure missing channels in `agents/.env`:")
        lines.append("  SLACK_WEBHOOK_URL, SMTP_HOST/USER/PASS/TO, PAGERDUTY_ROUTING_KEY")

        return "\n".join(lines)
    except Exception as exc:
        return f"Alert test error: {exc}"


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run(transport="stdio")

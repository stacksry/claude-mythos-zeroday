"""
reporter_agent.py

Generates a remediation report from the orchestrator's run results.
Produces a markdown report covering:
  - Overall hygiene score
  - Per-hack summary (impacted repos, fix status, test results)
  - Action items for unfixed/failed items
"""

import json
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
import anthropic


MODEL = "claude-opus-4-6"
REPORTS_DIR = Path(__file__).parent.parent / "reports"


@dataclass
class HackResult:
    hack_id: str
    hack_title: str
    severity: str
    impacted_repos: list[dict] = field(default_factory=list)
    fix_results: list[dict] = field(default_factory=list)   # [{repo, pr_url, success, notes}]
    test_results: list[dict] = field(default_factory=list)  # [{repo, passed, verdict, checks}]


def _severity_score(severity: str) -> int:
    return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(severity, 0)


def _hygiene_score(results: list[HackResult]) -> float:
    """
    Score from 0-100.
    Each hack weighted by severity. Fixed+tested = full credit, fixed only = half, neither = 0.
    """
    if not results:
        return 100.0

    total_weight = sum(_severity_score(r.severity) for r in results)
    if total_weight == 0:
        return 100.0

    earned = 0
    for r in results:
        weight = _severity_score(r.severity)
        if not r.impacted_repos:
            earned += weight  # not vulnerable → full credit
            continue
        fixed = sum(1 for f in r.fix_results if f.get("success"))
        tested_passed = sum(1 for t in r.test_results if t.get("passed"))
        total = len(r.impacted_repos)
        fix_rate = fixed / total if total else 0
        test_rate = tested_passed / total if total else 0
        earned += weight * (fix_rate * 0.5 + test_rate * 0.5)

    return round((earned / total_weight) * 100, 1)


def generate_report(
    org_name: str,
    results: list[HackResult],
    run_id: Optional[str] = None,
) -> Path:
    """
    Generate a markdown remediation report and save it to reports/.
    Returns the path to the generated file.
    """
    run_id = run_id or datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    score = _hygiene_score(results)
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # Ask Claude to write the executive summary
    client = anthropic.Anthropic()
    summary_prompt = (
        f"Write a 2-3 paragraph executive summary for a security remediation report.\n"
        f"Org: {org_name}\n"
        f"Hygiene score: {score}/100\n"
        f"Hacks analyzed: {len(results)}\n"
        f"Results:\n{json.dumps([{'hack': r.hack_title, 'severity': r.severity, "
        f"'impacted': len(r.impacted_repos), 'fixed': sum(1 for f in r.fix_results if f.get('success')), "
        f"'tests_passed': sum(1 for t in r.test_results if t.get('passed'))} for r in results], indent=2)}\n\n"
        "Be direct and technical. Focus on what was found, what was fixed, and what still needs attention."
    )
    exec_summary = ""
    response = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        messages=[{"role": "user", "content": summary_prompt}],
    )
    for block in response.content:
        if block.type == "text":
            exec_summary = block.text.strip()

    # Build the markdown report
    lines = [
        f"# Glasswing Remediation Report",
        f"",
        f"**Org:** `{org_name}`  ",
        f"**Run ID:** `{run_id}`  ",
        f"**Generated:** {timestamp}  ",
        f"**Hygiene Score:** {score}/100",
        f"",
        f"---",
        f"",
        f"## Executive Summary",
        f"",
        exec_summary,
        f"",
        f"---",
        f"",
        f"## Status Table",
        f"",
        f"| Hack | Severity | Impacted Repos | Fixed | Tests Passed |",
        f"|---|---|---|---|---|",
    ]

    for r in results:
        impacted = len(r.impacted_repos)
        fixed = sum(1 for f in r.fix_results if f.get("success"))
        tested = sum(1 for t in r.test_results if t.get("passed"))
        lines.append(
            f"| {r.hack_title} | {r.severity} | {impacted} | {fixed}/{impacted} | {tested}/{impacted} |"
        )

    lines += ["", "---", "", "## Detailed Results", ""]

    for r in results:
        lines += [
            f"### {r.hack_title}",
            f"",
            f"**Severity:** {r.severity}  ",
            f"**Hack ID:** `{r.hack_id}`",
            f"",
        ]

        if not r.impacted_repos:
            lines += ["**Result:** No impacted repos found. Org is not vulnerable to this hack.", ""]
            continue

        lines += ["**Impacted Repos:**", ""]
        for repo in r.impacted_repos:
            lines.append(
                f"- `{repo.get('repo', '?')}` — {repo.get('file', '')} "
                f"_(confidence: {repo.get('confidence', '?')})_"
            )
        lines.append("")

        if r.fix_results:
            lines += ["**Fix Results:**", ""]
            for fix in r.fix_results:
                status = "✅" if fix.get("success") else "❌"
                pr = fix.get("pr_url") or "no PR"
                lines.append(f"- {status} `{fix.get('repo', '?')}` — [{pr}]({pr})")
                if fix.get("notes"):
                    lines.append(f"  > {fix['notes']}")
            lines.append("")

        if r.test_results:
            lines += ["**Test Results:**", ""]
            for test in r.test_results:
                status = "✅" if test.get("passed") else "❌"
                lines.append(f"- {status} `{test.get('repo', '?')}`")
                if test.get("verdict"):
                    lines.append(f"  > {test['verdict']}")
                for check in test.get("checks", []):
                    lines.append(f"  - {check}")
            lines.append("")

    # Action items
    action_items = []
    for r in results:
        unfixed = [
            repo for repo in r.impacted_repos
            if not any(f.get("repo") == repo.get("repo") and f.get("success")
                       for f in r.fix_results)
        ]
        for repo in unfixed:
            action_items.append(
                f"- [ ] Apply fix for **{r.hack_title}** ({r.severity}) in `{repo.get('repo')}`"
            )
        failed_tests = [t for t in r.test_results if not t.get("passed")]
        for test in failed_tests:
            action_items.append(
                f"- [ ] Fix test failure for **{r.hack_title}** in `{test.get('repo')}`: "
                f"{test.get('verdict', '')[:100]}"
            )

    if action_items:
        lines += ["---", "", "## Action Items", ""] + action_items + [""]

    lines += [
        "---",
        "",
        f"*Generated by Project Glasswing / claude-mythos-zeroday*",
        f"*Model: {MODEL} | Score: {score}/100*",
    ]

    # Write to file
    REPORTS_DIR.mkdir(exist_ok=True)
    report_path = REPORTS_DIR / f"remediation_{run_id}.md"
    report_path.write_text("\n".join(lines))
    print(f"[reporter] Report saved: {report_path}")
    return report_path

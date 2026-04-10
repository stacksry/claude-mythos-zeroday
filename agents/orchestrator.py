"""
orchestrator.py

Main entry point for the Glasswing remediation pipeline.

Pipeline per hack:
  1. scanner_agent  → find impacted repos in the org
  2. fixer_agent    → apply fix + open PR for each impacted repo
  3. tester_agent   → assert the fix is correct
  4. reporter_agent → generate final remediation report

Usage:
    python orchestrator.py --org <github-org> [--hack <hack-id>] [--dry-run]
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

from hack_registry import load_hacks, Hack
import scanner_agent
import fixer_agent
import tester_agent
from reporter_agent import generate_report, HackResult


load_dotenv()


def _check_env():
    missing = [v for v in ["ANTHROPIC_API_KEY", "GITHUB_TOKEN"] if not os.environ.get(v)]
    if missing:
        print(f"[orchestrator] Missing environment variables: {', '.join(missing)}")
        print("  Set them in a .env file or export them before running.")
        sys.exit(1)


def _print_banner(org: str, hacks: list[Hack], dry_run: bool):
    print()
    print("=" * 60)
    print("  Glasswing Remediation Pipeline")
    print("=" * 60)
    print(f"  Org        : {org}")
    print(f"  Hacks      : {len(hacks)}")
    print(f"  Mode       : {'DRY RUN (no PRs will be created)' if dry_run else 'LIVE'}")
    print("=" * 60)
    for h in hacks:
        print(f"  [{h.severity:8}] {h.title}")
    print("=" * 60)
    print()


def run_pipeline(org: str, hack_filter: str | None, dry_run: bool) -> Path:
    """
    Run the full remediation pipeline.
    Returns path to the generated report.
    """
    _check_env()
    all_hacks = load_hacks()
    if not all_hacks:
        print("[orchestrator] No hacks found. Add research docs to research/ first.")
        sys.exit(1)

    hacks = [h for h in all_hacks if not hack_filter or hack_filter in h.id]
    if not hacks:
        print(f"[orchestrator] No hacks match filter '{hack_filter}'")
        sys.exit(1)

    _print_banner(org, hacks, dry_run)
    run_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    all_results: list[HackResult] = []

    for idx, hack in enumerate(hacks, 1):
        print(f"\n[{idx}/{len(hacks)}] Processing: {hack.title}")
        print(f"  Severity : {hack.severity}")
        print(f"  Patterns : {hack.scan_patterns}")
        result = HackResult(
            hack_id=hack.id,
            hack_title=hack.title,
            severity=hack.severity,
        )

        # ── Step 1: Scan ──────────────────────────────────────────────
        print(f"\n  [SCAN] Searching org '{org}' for vulnerable repos...")
        impacted = scanner_agent.scan(org, hack)
        result.impacted_repos = impacted

        if not impacted:
            print("  [SCAN] No impacted repos found.")
            all_results.append(result)
            continue

        print(f"  [SCAN] Found {len(impacted)} impacted repo(s):")
        for r in impacted:
            print(f"    - {r.get('repo')} ({r.get('file')}) [{r.get('confidence')} confidence]")

        if dry_run:
            print("  [DRY RUN] Skipping fix and test steps.")
            all_results.append(result)
            continue

        # ── Step 2: Fix ───────────────────────────────────────────────
        for impacted_repo in impacted:
            repo_name = impacted_repo.get("repo")
            file_path = impacted_repo.get("file")
            print(f"\n  [FIX] Applying fix to {repo_name} / {file_path}...")

            fix_result = fixer_agent.apply_fix(repo_name, file_path, hack)
            fix_result["repo"] = repo_name
            result.fix_results.append(fix_result)

            if fix_result.get("success"):
                print(f"  [FIX] ✅ PR opened: {fix_result.get('pr_url')}")
            else:
                print(f"  [FIX] ❌ Failed: {fix_result.get('notes')}")
                continue

            # ── Step 3: Test ──────────────────────────────────────────
            print(f"  [TEST] Asserting fix for {repo_name}...")
            test_result = tester_agent.assert_fix(
                repo_name,
                fix_result["pr_url"],
                fix_result["branch"],
                file_path,
                hack,
            )
            test_result["repo"] = repo_name
            result.test_results.append(test_result)

            status = "✅ PASSED" if test_result.get("passed") else "❌ FAILED"
            print(f"  [TEST] {status} — {test_result.get('verdict', '')[:120]}")

        all_results.append(result)

    # ── Step 4: Report ────────────────────────────────────────────────
    print("\n[REPORT] Generating remediation report...")
    report_path = generate_report(org, all_results, run_id)
    print(f"[REPORT] Done: {report_path}")

    # Print summary
    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    for r in all_results:
        impacted = len(r.impacted_repos)
        fixed = sum(1 for f in r.fix_results if f.get("success"))
        tested = sum(1 for t in r.test_results if t.get("passed"))
        print(f"  {r.hack_title}")
        print(f"    Impacted: {impacted}  Fixed: {fixed}  Tests Passed: {tested}")
    print("=" * 60)
    print(f"  Report: {report_path}")
    print("=" * 60)

    return report_path


def main():
    parser = argparse.ArgumentParser(
        description="Glasswing Remediation Pipeline — scan, fix, test, and report."
    )
    parser.add_argument(
        "--org", required=True,
        help="GitHub organization to scan (e.g. 'stacksry' or 'my-company')"
    )
    parser.add_argument(
        "--hack", default=None,
        help="Filter to a specific hack ID (substring match). Omit to run all hacks."
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Scan only — do not apply fixes or open PRs."
    )
    args = parser.parse_args()
    run_pipeline(args.org, args.hack, args.dry_run)


if __name__ == "__main__":
    main()

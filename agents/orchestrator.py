"""
orchestrator.py

Async/parallel Glasswing remediation pipeline.

Pipeline per hack:
  1. ranker_agent    → score files 1-5 for vulnerability likelihood
  2. scanner_agent   → find impacted repos (parallel per file batch)
  3. validator_agent → noise filter — confirm each finding is real
  4. triage_agent    → CVSS score, route by severity
  5. fixer_agent     → apply fix + open PR
  6. tester_agent    → assert the fix is correct
  7. reporter_agent  → generate final remediation report
  8. disclosure_agent (run separately, daily cron) → 90-day disclosure lifecycle

Priority queue: Critical and High hacks processed before Medium/Low.
Surge mode: --workers N scales parallel file-batch agents.

Usage:
    python orchestrator.py --org <github-org> [--hack <hack-id>] [--dry-run] [--workers 4]
"""

import argparse
import asyncio
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
import validator_agent
import triage_agent
from reporter_agent import generate_report, HackResult


load_dotenv()

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _check_env():
    missing = [v for v in ["ANTHROPIC_API_KEY", "GITHUB_TOKEN"] if not os.environ.get(v)]
    if missing:
        print(f"[orchestrator] Missing environment variables: {', '.join(missing)}")
        print("  Set them in a .env file or export them before running.")
        sys.exit(1)


def _print_banner(org: str, hacks: list[Hack], dry_run: bool, workers: int):
    print()
    print("=" * 60)
    print("  Glasswing Remediation Pipeline  (async/parallel)")
    print("=" * 60)
    print(f"  Org        : {org}")
    print(f"  Hacks      : {len(hacks)}")
    print(f"  Workers    : {workers}")
    print(f"  Mode       : {'DRY RUN (no PRs will be created)' if dry_run else 'LIVE'}")
    print("=" * 60)
    for h in sorted(hacks, key=lambda x: SEVERITY_ORDER.get(x.severity, 99)):
        print(f"  [{h.severity:8}] {h.title}")
    print("=" * 60)
    print()


async def _process_hack(
    hack: Hack,
    org: str,
    dry_run: bool,
    semaphore: asyncio.Semaphore,
    idx: int,
    total: int,
) -> HackResult:
    """Process a single hack through the full pipeline (async-safe)."""
    async with semaphore:
        result = HackResult(
            hack_id=hack.id,
            hack_title=hack.title,
            severity=hack.severity,
        )

        print(f"\n[{idx}/{total}] {hack.title} ({hack.severity})")

        # ── Step 1: Scan (parallel file batches via ranker) ──────────────
        print(f"  [SCAN] Ranking + scanning org '{org}'...")
        # Run blocking scanner in thread pool so we don't block the event loop
        loop = asyncio.get_event_loop()
        impacted = await loop.run_in_executor(None, scanner_agent.scan, org, hack)
        result.impacted_repos = impacted

        if not impacted:
            print(f"  [SCAN] No impacted repos found for {hack.id}")
            return result

        print(f"  [SCAN] {len(impacted)} finding(s):")
        for f in impacted:
            print(f"    - {f.get('repo')} / {f.get('file')} "
                  f"[{f.get('layer_hit', 'L?')}] confidence={f.get('confidence', '?')}")

        # ── Step 2: Validate — filter false positives ─────────────────────
        print(f"  [VALIDATE] Running noise filter...")
        confirmed = await loop.run_in_executor(
            None, validator_agent.validate_batch, impacted, hack
        )

        if not confirmed:
            print(f"  [VALIDATE] All findings rejected as false positives.")
            return result

        print(f"  [VALIDATE] {len(confirmed)}/{len(impacted)} findings confirmed.")

        # ── Step 3: Triage — CVSS score + route ──────────────────────────
        print(f"  [TRIAGE] CVSS scoring and routing...")
        queues = await loop.run_in_executor(
            None, triage_agent.triage_batch, confirmed, hack
        )

        human = queues.get("human_review", [])
        auto = queues.get("auto_fix", []) + queues.get("auto_fix_batched", [])
        backlog = queues.get("backlog", [])

        if human:
            print(f"  [TRIAGE] ⚠️  {len(human)} finding(s) → HUMAN REVIEW REQUIRED")
        if auto:
            print(f"  [TRIAGE] {len(auto)} finding(s) → auto-fix pipeline")
        if backlog:
            print(f"  [TRIAGE] {len(backlog)} finding(s) → backlog")

        if dry_run:
            print(f"  [DRY RUN] Skipping fix and test steps.")
            return result

        # ── Step 4: Fix (auto-fix queue only; human_review needs sign-off) ─
        fix_targets = auto  # Human review queue handled separately
        if not fix_targets:
            if human:
                print(f"  [FIX] Critical findings queued for human review — skipping auto-fix.")
            return result

        for finding, triage_record in fix_targets:
            repo_name = finding.get("repo")
            file_path = finding.get("file")
            print(f"\n  [FIX] {repo_name} / {file_path} (CVSS {triage_record.cvss_score})...")

            fix_result = await loop.run_in_executor(
                None, fixer_agent.apply_fix, repo_name, file_path, hack
            )
            fix_result["repo"] = repo_name
            result.fix_results.append(fix_result)

            if fix_result.get("success"):
                print(f"  [FIX] PR opened: {fix_result.get('pr_url')}")
            else:
                print(f"  [FIX] Failed: {fix_result.get('notes')}")
                continue

            # ── Step 5: Test ──────────────────────────────────────────────
            print(f"  [TEST] Asserting fix for {repo_name}...")
            test_result = await loop.run_in_executor(
                None,
                tester_agent.assert_fix,
                repo_name,
                fix_result["pr_url"],
                fix_result["branch"],
                file_path,
                hack,
            )
            test_result["repo"] = repo_name
            result.test_results.append(test_result)

            status = "PASSED" if test_result.get("passed") else "FAILED"
            print(f"  [TEST] {status} — {test_result.get('verdict', '')[:100]}")

        return result


async def _run_pipeline_async(
    org: str, hack_filter: str | None, dry_run: bool, workers: int
) -> Path:
    _check_env()
    all_hacks = load_hacks()
    if not all_hacks:
        print("[orchestrator] No hacks found. Add research docs to research/ first.")
        sys.exit(1)

    hacks = [h for h in all_hacks if not hack_filter or hack_filter in h.id]
    if not hacks:
        print(f"[orchestrator] No hacks match filter '{hack_filter}'")
        sys.exit(1)

    # Priority queue — Critical first, then High, Medium, Low
    hacks_sorted = sorted(hacks, key=lambda h: SEVERITY_ORDER.get(h.severity, 99))

    _print_banner(org, hacks, dry_run, workers)
    run_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    # Semaphore caps parallel workers
    semaphore = asyncio.Semaphore(workers)

    tasks = [
        _process_hack(hack, org, dry_run, semaphore, idx + 1, len(hacks_sorted))
        for idx, hack in enumerate(hacks_sorted)
    ]

    all_results: list[HackResult] = await asyncio.gather(*tasks)

    # ── Step 6: Report ────────────────────────────────────────────────────
    print("\n[REPORT] Generating remediation report...")
    report_path = generate_report(org, list(all_results), run_id)
    print(f"[REPORT] Done: {report_path}")

    # Summary
    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    for r in all_results:
        n_impacted = len(r.impacted_repos)
        n_fixed = sum(1 for f in r.fix_results if f.get("success"))
        n_passed = sum(1 for t in r.test_results if t.get("passed"))
        print(f"  [{r.severity:8}] {r.hack_title}")
        print(f"             Impacted={n_impacted}  Fixed={n_fixed}  Tests OK={n_passed}")
    print("=" * 60)
    print(f"  Report : {report_path}")
    print(f"  Run ID : {run_id}")
    print("=" * 60)
    print()
    print("  Next: run disclosure_agent.py daily to manage 90-day disclosure timelines.")
    print()

    return report_path


def run_pipeline(org: str, hack_filter: str | None, dry_run: bool, workers: int = 4) -> Path:
    return asyncio.run(_run_pipeline_async(org, hack_filter, dry_run, workers))


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
    parser.add_argument(
        "--workers", type=int, default=4,
        help="Number of parallel hack-processing workers (default: 4). "
             "Increase for surge mode when volume spikes."
    )
    args = parser.parse_args()
    run_pipeline(args.org, args.hack, args.dry_run, args.workers)


if __name__ == "__main__":
    main()

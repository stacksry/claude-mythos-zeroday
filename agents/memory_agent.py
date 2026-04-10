"""
memory_agent.py

Persistent learning store for the Glasswing pipeline.

Agents read from memory at startup — examples are injected as few-shot
context into Claude prompts, making each run smarter than the last.
Agents write back to memory after outcomes — closing the feedback loop.

Five feedback loops:

  1. fix_patterns         ← fixer_agent writes after PR merged/CI passed
                            fixer_agent reads to reuse proven fix templates

  2. false_positive_signals ← validator_agent writes on every REJECTED verdict
                              validator_agent reads to pre-filter future findings

  3. cvss_corrections     ← triage_agent reads; written by record_cvss_correction()
                            (called when a human overrides a CVSS score)

  4. ranker_calibrations  ← ranker_agent reads; written when a low-ranked file
                            turns out to contain a real finding (from triage)

  5. confirmed_scan_patterns ← sandbox_agent writes on CONFIRMED_EXPLOITABLE
                               scanner_agent reads to extend hack.scan_patterns at runtime

Storage: reports/memory/*.json — plain JSON, human-readable and git-trackable.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Optional

MEMORY_DIR = Path(__file__).parent.parent / "reports" / "memory"

# ── Record types ──────────────────────────────────────────────────────────────

@dataclass
class FixPattern:
    hack_id: str
    language: str
    file_extension: str          # ".java", ".py", ".c", etc.
    vulnerable_snippet: str      # abbreviated — key lines only (≤10 lines)
    fix_snippet: str             # the actual fix applied (≤10 lines)
    repo: str
    confirmed_by: str            # "ci_pass" | "tester_agent" | "human"
    confirmed_at: str            # ISO8601
    confidence: int = 1          # incremented each time this pattern is reused


@dataclass
class FalsePositiveSignal:
    hack_id: str
    file_pattern: str            # path pattern that triggered the FP (e.g. "*/test/*")
    rejection_reason: str        # false_positive | theoretical | already_patched | low_impact
    signal: str                  # plain-English description of what made it a FP
    recorded_at: str
    count: int = 1               # incremented on repeated occurrences


@dataclass
class CvssCorrection:
    hack_id: str
    original_score: float
    corrected_score: float
    original_vector: str
    corrected_vector: str
    reason: str                  # why the correction was made
    recorded_at: str


@dataclass
class RankerCalibration:
    file_path_pattern: str       # e.g. "*/config/*", "*/util/*"
    file_extension: str          # ".java", ".py", etc.
    ranked_score: int            # what ranker assigned (1–5)
    actual_severity: str         # what triage found: Critical | High | Medium | Low
    hack_id: str
    lesson: str                  # plain-English: "config parsers can contain deserialization"
    recorded_at: str


@dataclass
class ConfirmedScanPattern:
    hack_id: str
    pattern: str                 # the code pattern confirmed exploitable
    language: str
    crash_indicator: str         # what in sandbox output confirmed it
    confirmed_by: str            # "sandbox" | "human"
    recorded_at: str
    count: int = 1


# ── Store class ───────────────────────────────────────────────────────────────

class MemoryStore:
    """
    Thin wrapper around JSON files in reports/memory/.
    All operations are synchronous and file-based — no database required.
    """

    def __init__(self, memory_dir: Path = MEMORY_DIR):
        self.dir = memory_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        self._files = {
            "fix_patterns":            self.dir / "fix_patterns.json",
            "false_positive_signals":  self.dir / "false_positive_signals.json",
            "cvss_corrections":        self.dir / "cvss_corrections.json",
            "ranker_calibrations":     self.dir / "ranker_calibrations.json",
            "confirmed_scan_patterns": self.dir / "confirmed_scan_patterns.json",
        }

    def _load(self, key: str) -> list:
        path = self._files[key]
        if not path.exists():
            return []
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return []

    def _save(self, key: str, records: list):
        self._files[key].write_text(json.dumps(records, indent=2))

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ── Write operations ──────────────────────────────────────────────────────

    def record_fix_pattern(
        self,
        hack_id: str,
        language: str,
        file_extension: str,
        vulnerable_snippet: str,
        fix_snippet: str,
        repo: str,
        confirmed_by: str = "tester_agent",
    ):
        """
        Record a proven fix pattern after a PR is confirmed to be correct.
        If an identical pattern already exists, increment its confidence score.
        """
        records = self._load("fix_patterns")

        # Dedup by hack_id + fix_snippet fingerprint
        for r in records:
            if r["hack_id"] == hack_id and r["fix_snippet"][:100] == fix_snippet[:100]:
                r["confidence"] = r.get("confidence", 1) + 1
                r["confirmed_at"] = self._now()
                self._save("fix_patterns", records)
                return

        records.append(asdict(FixPattern(
            hack_id=hack_id,
            language=language,
            file_extension=file_extension,
            vulnerable_snippet=vulnerable_snippet[:500],
            fix_snippet=fix_snippet[:500],
            repo=repo,
            confirmed_by=confirmed_by,
            confirmed_at=self._now(),
        )))
        self._save("fix_patterns", records)

    def record_false_positive(
        self,
        hack_id: str,
        file_path: str,
        rejection_reason: str,
        signal: str,
    ):
        """
        Record what made a finding a false positive.
        Extracts a path pattern from the full file path (e.g. "*/test/*").
        """
        # Generalise the file path to a pattern
        parts = Path(file_path).parts
        test_like = {"test", "tests", "spec", "specs", "mock", "mocks", "fixture", "fixtures"}
        pattern_parts = []
        for p in parts:
            if p.lower() in test_like:
                pattern_parts.append(p)
            elif len(pattern_parts) > 0:
                pattern_parts.append("*")
                break
        file_pattern = ("*/" + "/".join(pattern_parts) + "/*") if pattern_parts else file_path

        records = self._load("false_positive_signals")
        for r in records:
            if r["hack_id"] == hack_id and r["signal"][:80] == signal[:80]:
                r["count"] = r.get("count", 1) + 1
                self._save("false_positive_signals", records)
                return

        records.append(asdict(FalsePositiveSignal(
            hack_id=hack_id,
            file_pattern=file_pattern,
            rejection_reason=rejection_reason,
            signal=signal[:300],
            recorded_at=self._now(),
        )))
        self._save("false_positive_signals", records)

    def record_cvss_correction(
        self,
        hack_id: str,
        original_score: float,
        corrected_score: float,
        original_vector: str,
        corrected_vector: str,
        reason: str,
    ):
        """Record a human CVSS score override for future calibration."""
        records = self._load("cvss_corrections")
        records.append(asdict(CvssCorrection(
            hack_id=hack_id,
            original_score=original_score,
            corrected_score=corrected_score,
            original_vector=original_vector,
            corrected_vector=corrected_vector,
            reason=reason[:300],
            recorded_at=self._now(),
        )))
        self._save("cvss_corrections", records)

    def record_ranker_calibration(
        self,
        file_path: str,
        file_extension: str,
        ranked_score: int,
        actual_severity: str,
        hack_id: str,
        lesson: str,
    ):
        """
        Record when ranker scored a file too low and it turned out to be vulnerable.
        Only records misses (ranked_score < actual severity threshold).
        """
        severity_floor = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        if ranked_score >= severity_floor.get(actual_severity, 3):
            return  # Not a miss — ranker was correct

        parts = Path(file_path).parts
        pattern = "*/".join(["*"] + list(parts[-2:])) if len(parts) >= 2 else file_path

        records = self._load("ranker_calibrations")
        records.append(asdict(RankerCalibration(
            file_path_pattern=pattern,
            file_extension=file_extension,
            ranked_score=ranked_score,
            actual_severity=actual_severity,
            hack_id=hack_id,
            lesson=lesson[:300],
            recorded_at=self._now(),
        )))
        self._save("ranker_calibrations", records)

    def record_confirmed_scan_pattern(
        self,
        hack_id: str,
        pattern: str,
        language: str,
        crash_indicator: str,
        confirmed_by: str = "sandbox",
    ):
        """Record a code pattern that sandbox confirmed as exploitable."""
        records = self._load("confirmed_scan_patterns")
        for r in records:
            if r["hack_id"] == hack_id and r["pattern"] == pattern:
                r["count"] = r.get("count", 1) + 1
                self._save("confirmed_scan_patterns", records)
                return

        records.append(asdict(ConfirmedScanPattern(
            hack_id=hack_id,
            pattern=pattern,
            language=language,
            crash_indicator=crash_indicator[:200],
            confirmed_by=confirmed_by,
            recorded_at=self._now(),
        )))
        self._save("confirmed_scan_patterns", records)

    # ── Read operations (return formatted prompt context) ─────────────────────

    def get_fix_examples(self, hack_id: str, language: str, n: int = 3) -> str:
        """
        Return up to N proven fix examples for this hack+language as prompt context.
        Sorted by confidence (most-reused first).
        """
        records = self._load("fix_patterns")
        matches = [
            r for r in records
            if r["hack_id"] == hack_id and r["language"].lower() == language.lower()
        ]
        matches.sort(key=lambda r: r.get("confidence", 1), reverse=True)
        matches = matches[:n]

        if not matches:
            return ""

        lines = [
            f"\n## Proven fix patterns from previous runs (confidence-ranked)\n"
            f"Apply these patterns where applicable — they are confirmed working fixes:\n"
        ]
        for i, r in enumerate(matches, 1):
            lines.append(
                f"\n### Pattern {i} (confidence={r.get('confidence', 1)}, "
                f"confirmed by {r['confirmed_by']} in {r['repo']})\n"
                f"**Vulnerable:**\n```\n{r['vulnerable_snippet']}\n```\n"
                f"**Fixed:**\n```\n{r['fix_snippet']}\n```\n"
            )
        return "\n".join(lines)

    def get_false_positive_signals(self, hack_id: str, n: int = 5) -> str:
        """
        Return up to N false positive signals for this hack as prompt context.
        Sorted by frequency (most-common first).
        """
        records = self._load("false_positive_signals")
        matches = [r for r in records if r["hack_id"] == hack_id]
        matches.sort(key=lambda r: r.get("count", 1), reverse=True)
        matches = matches[:n]

        if not matches:
            return ""

        lines = [
            f"\n## Known false positive patterns for this vulnerability\n"
            f"REJECT findings that match these patterns — they are confirmed false positives:\n"
        ]
        for r in matches:
            lines.append(
                f"- [{r['rejection_reason']}] In files matching `{r['file_pattern']}`: "
                f"{r['signal']} (seen {r.get('count', 1)}x)"
            )
        return "\n".join(lines)

    def get_cvss_examples(self, hack_id: str, n: int = 3) -> str:
        """
        Return up to N CVSS correction examples for this hack as prompt context.
        """
        records = self._load("cvss_corrections")
        matches = [r for r in records if r["hack_id"] == hack_id][-n:]

        if not matches:
            return ""

        lines = [
            f"\n## Previous CVSS corrections for this vulnerability class\n"
            f"Use these calibrations when scoring:\n"
        ]
        for r in matches:
            lines.append(
                f"- Score was {r['original_score']} ({r['original_vector']}), "
                f"corrected to {r['corrected_score']} ({r['corrected_vector']}). "
                f"Reason: {r['reason']}"
            )
        return "\n".join(lines)

    def get_ranker_examples(self, n: int = 5) -> str:
        """
        Return up to N ranker mis-calibration examples as prompt context.
        """
        records = self._load("ranker_calibrations")
        if not records:
            return ""

        # Most recent first
        records = sorted(records, key=lambda r: r["recorded_at"], reverse=True)[:n]

        lines = [
            f"\n## Previously mis-ranked files (score too low — real vulns found)\n"
            f"Recalibrate scores for similar files:\n"
        ]
        for r in records:
            lines.append(
                f"- Files matching `{r['file_path_pattern']}` ({r['file_extension']}) "
                f"were scored {r['ranked_score']} but contained {r['actual_severity']} findings. "
                f"Lesson: {r['lesson']}"
            )
        return "\n".join(lines)

    def get_confirmed_patterns(self, hack_id: str) -> list[str]:
        """
        Return all sandbox-confirmed scan patterns for this hack.
        Used by scanner to extend hack.scan_patterns at runtime.
        """
        records = self._load("confirmed_scan_patterns")
        return [
            r["pattern"] for r in records
            if r["hack_id"] == hack_id
        ]

    def stats(self) -> dict:
        """Return a summary of stored memory for reporting."""
        return {
            key: len(self._load(key))
            for key in self._files
        }


# ── Module-level singleton ────────────────────────────────────────────────────

_store: Optional[MemoryStore] = None

def get_store() -> MemoryStore:
    global _store
    if _store is None:
        _store = MemoryStore()
    return _store


# ── Convenience functions (used by agents) ────────────────────────────────────

def get_fix_examples(hack_id: str, language: str, n: int = 3) -> str:
    return get_store().get_fix_examples(hack_id, language, n)

def get_false_positive_signals(hack_id: str, n: int = 5) -> str:
    return get_store().get_false_positive_signals(hack_id, n)

def get_cvss_examples(hack_id: str, n: int = 3) -> str:
    return get_store().get_cvss_examples(hack_id, n)

def get_ranker_examples(n: int = 5) -> str:
    return get_store().get_ranker_examples(n)

def get_confirmed_patterns(hack_id: str) -> list[str]:
    return get_store().get_confirmed_patterns(hack_id)

def record_fix_pattern(hack_id, language, file_extension, vulnerable_snippet,
                        fix_snippet, repo, confirmed_by="tester_agent"):
    get_store().record_fix_pattern(hack_id, language, file_extension,
                                    vulnerable_snippet, fix_snippet, repo, confirmed_by)

def record_false_positive(hack_id, file_path, rejection_reason, signal):
    get_store().record_false_positive(hack_id, file_path, rejection_reason, signal)

def record_cvss_correction(hack_id, original_score, corrected_score,
                            original_vector, corrected_vector, reason):
    get_store().record_cvss_correction(hack_id, original_score, corrected_score,
                                        original_vector, corrected_vector, reason)

def record_ranker_calibration(file_path, file_extension, ranked_score,
                               actual_severity, hack_id, lesson):
    get_store().record_ranker_calibration(file_path, file_extension, ranked_score,
                                          actual_severity, hack_id, lesson)

def record_confirmed_scan_pattern(hack_id, pattern, language, crash_indicator,
                                   confirmed_by="sandbox"):
    get_store().record_confirmed_scan_pattern(hack_id, pattern, language,
                                               crash_indicator, confirmed_by)


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    store = get_store()
    stats = store.stats()
    print("Glasswing Memory Store")
    print(f"  Location: {MEMORY_DIR}")
    print()
    for key, count in stats.items():
        print(f"  {key:<30} {count} record(s)")
    print()

    total = sum(stats.values())
    if total == 0:
        print("  No memory yet — run the pipeline to start learning.")
    else:
        print(f"  Total: {total} records across {len(stats)} feedback loops.")

"""
hack_registry.py

Loads vulnerability definitions from the research/ and fixes/ directories.
Each hack entry pairs a research doc with its corresponding fix doc.
"""

import os
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


REPO_ROOT = Path(__file__).parent.parent


@dataclass
class Hack:
    id: str                        # e.g. "2026-04-10_ffmpeg-oob-write"
    title: str                     # e.g. "FFmpeg Out-of-Bounds Write"
    severity: str                  # Critical / High / Medium / Low
    language: str                  # c, java, python, etc.
    scan_patterns: list[str]       # code patterns to search in org repos
    fix_description: str           # what the fix does
    research_path: Path
    fix_path: Optional[Path] = None
    raw_research: str = ""
    raw_fix: str = ""


def _extract_field(text: str, field: str) -> str:
    """Pull a value from markdown frontmatter or bold headers."""
    match = re.search(rf"\*\*{field}:\*\*\s*(.+)", text)
    if match:
        return match.group(1).strip()
    match = re.search(rf"{field}:\s*(.+)", text)
    if match:
        return match.group(1).strip()
    return ""


def _infer_language(text: str, filename: str) -> str:
    """Guess the primary language from the research doc content."""
    text_lower = text.lower() + filename.lower()
    if "java" in text_lower and "jvm" in text_lower:
        return "java"
    if "java" in text_lower:
        return "java"
    if ".c " in text_lower or "c/c++" in text_lower or "ffmpeg" in text_lower:
        return "c"
    if "python" in text_lower:
        return "python"
    if "javascript" in text_lower or "node" in text_lower:
        return "javascript"
    return "unknown"


def _extract_scan_patterns(research_text: str, fix_text: str) -> list[str]:
    """
    Extract code patterns (grep-friendly) that indicate the vulnerable pattern.
    Pulled from code blocks in research and fix docs.
    """
    patterns = []

    # Pull patterns from RED FLAG blocks in the fix doc
    red_flag_blocks = re.findall(r"RED FLAG.*?```.*?```", fix_text, re.DOTALL)
    for block in red_flag_blocks:
        code_match = re.search(r"```.*?\n(.*?)```", block, re.DOTALL)
        if code_match:
            code = code_match.group(1).strip()
            # Take the most distinctive line as a grep pattern
            lines = [l.strip() for l in code.splitlines() if l.strip() and not l.startswith("#")]
            if lines:
                patterns.append(lines[0])

    # Fall back: pull from research vulnerability class section
    if not patterns:
        vuln_section = re.search(
            r"### Root Cause(.*?)###", research_text, re.DOTALL
        )
        if vuln_section:
            code_block = re.search(r"```.*?\n(.*?)```", vuln_section.group(1), re.DOTALL)
            if code_block:
                lines = [l.strip() for l in code_block.group(1).splitlines()
                         if l.strip() and not l.startswith("//") and not l.startswith("#")]
                if lines:
                    patterns.append(lines[0])

    # Hardcoded fallbacks for known hacks in this repo
    if not patterns:
        if "deserialization" in research_text.lower():
            patterns = ["new ObjectInputStream(", "readObject()"]
        elif "oob" in research_text.lower() or "out-of-bounds" in research_text.lower():
            patterns = ["malloc(width * height)", "for (int i = 0; i < num_planes"]

    return patterns or ["# no pattern extracted — review manually"]


def load_hacks() -> list[Hack]:
    """
    Scan research/ and fixes/ directories and return a list of Hack entries.
    Pairs each research doc with its matching fix doc by shared date+name prefix.
    """
    research_dir = REPO_ROOT / "research"
    fixes_dir = REPO_ROOT / "fixes"
    hacks = []

    if not research_dir.exists():
        return []

    for research_file in sorted(research_dir.glob("*.md")):
        stem = research_file.stem  # e.g. "2026-04-10_ffmpeg-oob-write"
        raw_research = research_file.read_text()

        # Try to find matching fix doc
        fix_file = None
        for candidate in fixes_dir.glob("*.md") if fixes_dir.exists() else []:
            if stem.replace("_poc", "") in candidate.stem:
                fix_file = candidate
                break

        raw_fix = fix_file.read_text() if fix_file else ""

        # Extract metadata
        severity = _extract_field(raw_research, "Severity")
        language = _infer_language(raw_research, stem)
        scan_patterns = _extract_scan_patterns(raw_research, raw_fix)

        # Build title from filename
        title = stem.split("_", 1)[-1].replace("-", " ").title()
        if ":" not in title:
            title = f"[{language.upper()}] {title}"

        fix_description = ""
        if raw_fix:
            match = re.search(r"## The Fix.*?\n(.*?)##", raw_fix, re.DOTALL)
            if match:
                fix_description = match.group(1).strip()[:500]

        hacks.append(Hack(
            id=stem,
            title=title,
            severity=severity or "Unknown",
            language=language,
            scan_patterns=scan_patterns,
            fix_description=fix_description or "See fix doc for details.",
            research_path=research_file,
            fix_path=fix_file,
            raw_research=raw_research,
            raw_fix=raw_fix,
        ))

    return hacks


if __name__ == "__main__":
    for hack in load_hacks():
        print(f"[{hack.severity}] {hack.title}")
        print(f"  Language : {hack.language}")
        print(f"  Patterns : {hack.scan_patterns}")
        print()

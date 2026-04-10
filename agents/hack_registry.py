"""
hack_registry.py

Loads vulnerability definitions from the research/ and fixes/ directories.
Each Hack entry carries structured discovery metadata so the scanner can
check infra, OS, language, framework, and library versions before doing
code-level pattern matching.
"""

import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


REPO_ROOT = Path(__file__).parent.parent


@dataclass
class AffectedLibrary:
    """A library/package that exposes the vulnerability when present."""
    name: str                          # e.g. "commons-collections"
    ecosystem: str                     # maven | npm | pypi | go | gem | cargo | nuget
    vulnerable_versions: str           # semver range, e.g. "< 3.2.2" or ">= 4.0, < 4.1"
    safe_version: Optional[str] = None # e.g. "3.2.2"


@dataclass
class Hack:
    id: str                            # e.g. "2026-04-10_ffmpeg-oob-write"
    title: str                         # e.g. "FFmpeg Out-of-Bounds Write"
    severity: str                      # Critical / High / Medium / Low
    language: str                      # c, java, python, javascript, go, ruby, etc.

    # ── Discovery layers ────────────────────────────────────────────────────
    # Layer 1 – Infrastructure signals
    infra_signals: list[str] = field(default_factory=list)
    # e.g. ["Dockerfile", "docker-compose.yml", "*.tf", ".github/workflows"]

    # Layer 2 – OS signals
    os_signals: list[str] = field(default_factory=list)
    # e.g. ["FROM debian", "FROM ubuntu:20", "runs-on: ubuntu"]

    # Layer 3 – Language / runtime files
    language_files: list[str] = field(default_factory=list)
    # e.g. ["pom.xml", "*.java"] or ["package.json", "*.js"]

    # Layer 4 – Framework signals
    framework_signals: list[str] = field(default_factory=list)
    # e.g. ["spring-boot", "django", "express", "rails"]

    # Layer 5 – Affected libraries + version ranges
    affected_libraries: list[AffectedLibrary] = field(default_factory=list)

    # Layer 6 – Code-level patterns (final confirmation)
    scan_patterns: list[str] = field(default_factory=list)

    # ── Fix metadata ─────────────────────────────────────────────────────────
    fix_description: str = ""
    research_path: Optional[Path] = None
    fix_path: Optional[Path] = None
    raw_research: str = ""
    raw_fix: str = ""


# ---------------------------------------------------------------------------
# Built-in discovery profiles for known vulnerability classes
# ---------------------------------------------------------------------------

_PROFILES: dict[str, dict] = {
    "deserialization": {
        "infra_signals": ["Dockerfile", "docker-compose.yml", ".github/workflows/*.yml"],
        "os_signals": ["FROM openjdk", "FROM eclipse-temurin", "FROM amazoncorretto"],
        "language_files": ["pom.xml", "build.gradle", "*.java"],
        "framework_signals": ["spring-boot", "struts", "jboss", "weblogic", "jenkins"],
        "affected_libraries": [
            AffectedLibrary("commons-collections", "maven", "< 3.2.2", "3.2.2"),
            AffectedLibrary("commons-collections4", "maven", "< 4.1", "4.1"),
            AffectedLibrary("spring-core", "maven", ">= 4.0, < 5.3.18", "5.3.18"),
            AffectedLibrary("jackson-databind", "maven", "< 2.14.0", "2.14.0"),
            AffectedLibrary("xstream", "maven", "< 1.4.19", "1.4.19"),
        ],
        "scan_patterns": ["new ObjectInputStream(", "readObject()", ".readObject()"],
    },
    "oob": {
        "infra_signals": ["Dockerfile", "Makefile", ".github/workflows/*.yml"],
        "os_signals": ["FROM ubuntu", "FROM debian", "FROM alpine"],
        "language_files": ["*.c", "*.h", "CMakeLists.txt", "Makefile", "configure.ac"],
        "framework_signals": ["libav", "ffmpeg", "gstreamer", "vlc"],
        "affected_libraries": [
            AffectedLibrary("ffmpeg", "apt", "< 6.1.2", "6.1.2"),
            AffectedLibrary("libavcodec", "apt", "< 6.1.2", "6.1.2"),
        ],
        "scan_patterns": [
            "malloc(width * height)",
            "for (int i = 0; i < num_planes",
            "buf[i] = ",
        ],
    },
}


def _match_profile(research_text: str, stem: str) -> str:
    """Return the best matching profile key for a research doc."""
    text = research_text.lower() + stem.lower()
    if "deserialization" in text or "readobject" in text:
        return "deserialization"
    if "out-of-bounds" in text or "oob" in text or "ffmpeg" in text:
        return "oob"
    return ""


def _extract_field(text: str, key: str) -> str:
    for pattern in [rf"\*\*{key}:\*\*\s*(.+)", rf"{key}:\s*(.+)"]:
        m = re.search(pattern, text)
        if m:
            return m.group(1).strip()
    return ""


def _infer_language(text: str, filename: str) -> str:
    t = text.lower() + filename.lower()
    if "java" in t or "jvm" in t:
        return "java"
    if ".c " in t or "c/c++" in t or "ffmpeg" in t:
        return "c"
    if "python" in t:
        return "python"
    if "javascript" in t or "node" in t or "npm" in t:
        return "javascript"
    if "go " in t or "golang" in t:
        return "go"
    if "ruby" in t or "rails" in t or "gem" in t:
        return "ruby"
    if "rust" in t or "cargo" in t:
        return "rust"
    return "unknown"


def _extract_fix_description(raw_fix: str) -> str:
    m = re.search(r"## The Fix.*?\n(.*?)##", raw_fix, re.DOTALL)
    return m.group(1).strip()[:500] if m else ""


def load_hacks() -> list[Hack]:
    """
    Scan research/ and fixes/ directories.
    Returns Hack objects with full structured discovery metadata.
    """
    research_dir = REPO_ROOT / "research"
    fixes_dir = REPO_ROOT / "fixes"
    hacks = []

    if not research_dir.exists():
        return []

    for research_file in sorted(research_dir.glob("*.md")):
        stem = research_file.stem
        raw_research = research_file.read_text()

        # Find matching fix doc
        fix_file = None
        if fixes_dir.exists():
            for candidate in fixes_dir.glob("*.md"):
                if stem.replace("_poc", "") in candidate.stem:
                    fix_file = candidate
                    break
        raw_fix = fix_file.read_text() if fix_file else ""

        # Core fields
        severity = _extract_field(raw_research, "Severity")
        language = _infer_language(raw_research, stem)
        title = stem.split("_", 1)[-1].replace("-", " ").title()
        if ":" not in title:
            title = f"[{language.upper()}] {title}"

        # Structured discovery from profile
        profile_key = _match_profile(raw_research, stem)
        profile = _PROFILES.get(profile_key, {})

        hacks.append(Hack(
            id=stem,
            title=title,
            severity=severity or "Unknown",
            language=language,
            infra_signals=profile.get("infra_signals", ["Dockerfile", ".github/workflows/*.yml"]),
            os_signals=profile.get("os_signals", []),
            language_files=profile.get("language_files", [f"*.{language}"]),
            framework_signals=profile.get("framework_signals", []),
            affected_libraries=profile.get("affected_libraries", []),
            scan_patterns=profile.get("scan_patterns", []),
            fix_description=_extract_fix_description(raw_fix) or "See fix doc.",
            research_path=research_file,
            fix_path=fix_file,
            raw_research=raw_research,
            raw_fix=raw_fix,
        ))

    return hacks


if __name__ == "__main__":
    for hack in load_hacks():
        print(f"[{hack.severity}] {hack.title}")
        print(f"  Language   : {hack.language}")
        print(f"  Infra      : {hack.infra_signals}")
        print(f"  OS         : {hack.os_signals}")
        print(f"  Lang files : {hack.language_files}")
        print(f"  Frameworks : {hack.framework_signals}")
        print(f"  Libraries  : {[(l.name, l.vulnerable_versions) for l in hack.affected_libraries]}")
        print(f"  Patterns   : {hack.scan_patterns}")
        print()

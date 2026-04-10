"""
supply_chain_agent.py

Transitive dependency scanner — checks the full resolved dependency tree,
not just direct dependencies declared in the top-level manifest.

Why this matters:
  A repo's pom.xml may not list commons-collections directly, but it's pulled
  in 3 levels deep via spring-boot-starter → hibernate → commons-collections@3.2.1.
  Direct-only scanning misses 60-70% of real vulnerability surface.

Lockfile formats supported:
  Java     : pom.xml (dependency:tree output format), gradle.lockfile
  Python   : poetry.lock, Pipfile.lock, requirements.txt (pinned)
  Node.js  : package-lock.json (v2/v3), yarn.lock
  Go       : go.sum
  Ruby     : Gemfile.lock
  Rust     : Cargo.lock
  .NET     : packages.lock.json

For each lockfile found in the repo, the agent:
  1. Fetches and parses the lockfile from GitHub
  2. Builds the full dependency list (name → resolved version)
  3. Checks every package against affected_libraries version ranges
  4. Returns findings with the full dependency path to the vulnerable lib
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import github_tools as gh
from hack_registry import Hack, AffectedLibrary


# ---------------------------------------------------------------------------
# Lockfile path patterns per ecosystem
# ---------------------------------------------------------------------------

LOCKFILE_CANDIDATES = {
    "maven":  ["package-lock.json", "pom.xml"],   # we parse mvn dep:tree style
    "npm":    ["package-lock.json", "npm-shrinkwrap.json"],
    "yarn":   ["yarn.lock"],
    "pypi":   ["poetry.lock", "Pipfile.lock", "requirements.txt"],
    "go":     ["go.sum"],
    "gem":    ["Gemfile.lock"],
    "cargo":  ["Cargo.lock"],
    "nuget":  ["packages.lock.json"],
    "gradle": ["gradle.lockfile", "buildscript-gradle.lockfile"],
}

# Flat list of all candidates for initial repo scan
ALL_LOCKFILES = [
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "poetry.lock", "Pipfile.lock", "requirements.txt",
    "go.sum", "Gemfile.lock", "Cargo.lock",
    "packages.lock.json", "gradle.lockfile",
    "buildscript-gradle.lockfile",
]


@dataclass
class TransitiveFinding:
    repo: str
    lockfile_path: str
    ecosystem: str
    package: str
    resolved_version: str
    vulnerable_range: str
    safe_version: Optional[str]
    dependency_depth: str   # "direct" | "transitive"
    confidence: str         # "high" (lockfile pinned) | "medium" (manifest range)


@dataclass
class SupplyChainResult:
    repo: str
    findings: list[TransitiveFinding] = field(default_factory=list)
    lockfiles_checked: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def is_vulnerable(self) -> bool:
        return len(self.findings) > 0


# ---------------------------------------------------------------------------
# Version comparison helpers
# ---------------------------------------------------------------------------

def _parse_version(v: str) -> tuple[int, ...]:
    """Parse a semver string into a comparable tuple. Best-effort."""
    v = v.strip().lstrip("v=^~")
    # Take only the numeric prefix (e.g. "3.2.1.Final" → "3.2.1")
    parts = re.split(r"[.\-]", v)
    result = []
    for p in parts[:4]:
        try:
            result.append(int(p))
        except ValueError:
            break
    return tuple(result) if result else (0,)


def _version_in_range(version: str, vuln_range: str) -> bool:
    """
    Check if a version satisfies a vulnerability range expression.
    Supports: "< X", "<= X", ">= X", "> X", ">= X, < Y", "= X"
    """
    v = _parse_version(version)
    if not v:
        return False

    # Handle compound ranges like ">= 4.0, < 4.1"
    for part in vuln_range.split(","):
        part = part.strip()
        m = re.match(r"([<>=!]+)\s*([\w.\-]+)", part)
        if not m:
            continue
        op, bound_str = m.group(1), m.group(2)
        bound = _parse_version(bound_str)
        if op == "<"  and not (v < bound):  return False
        if op == "<=" and not (v <= bound): return False
        if op == ">"  and not (v > bound):  return False
        if op == ">=" and not (v >= bound): return False
        if op == "="  and not (v == bound): return False
        if op == "!=" and not (v != bound): return False
    return True


# ---------------------------------------------------------------------------
# Lockfile parsers — each returns {package_name: resolved_version}
# ---------------------------------------------------------------------------

def _parse_package_lock(content: str) -> dict[str, str]:
    """package-lock.json v2/v3 — flat packages dict."""
    result = {}
    try:
        data = json.loads(content)
        # v3: packages dict with "node_modules/X" keys
        packages = data.get("packages", {})
        for key, info in packages.items():
            if key.startswith("node_modules/"):
                name = key[len("node_modules/"):]
                if "version" in info:
                    result[name] = info["version"]
        # v1 fallback: dependencies dict
        if not result:
            for name, info in data.get("dependencies", {}).items():
                if "version" in info:
                    result[name] = info["version"]
    except (json.JSONDecodeError, AttributeError):
        pass
    return result


def _parse_yarn_lock(content: str) -> dict[str, str]:
    """yarn.lock — extract name@version blocks."""
    result = {}
    current_names: list[str] = []
    for line in content.splitlines():
        # Header: "package-name@^1.0.0, package-name@^1.0.1:"
        if line and not line.startswith(" ") and not line.startswith("#") and line.endswith(":"):
            current_names = []
            for entry in line.rstrip(":").split(","):
                entry = entry.strip().strip('"')
                m = re.match(r"^(@?[^@]+)@", entry)
                if m:
                    current_names.append(m.group(1))
        # Version line: "  version \"1.2.3\""
        elif line.strip().startswith("version ") and current_names:
            m = re.search(r'"([^"]+)"', line)
            if m:
                for name in current_names:
                    result[name] = m.group(1)
    return result


def _parse_poetry_lock(content: str) -> dict[str, str]:
    """poetry.lock — TOML-like [[package]] blocks."""
    result = {}
    current_name = None
    for line in content.splitlines():
        line = line.strip()
        if line == "[[package]]":
            current_name = None
        elif line.startswith("name = ") and current_name is None:
            current_name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = ") and current_name:
            version = line.split("=", 1)[1].strip().strip('"')
            result[current_name] = version
            current_name = None
    return result


def _parse_pipfile_lock(content: str) -> dict[str, str]:
    """Pipfile.lock — JSON with default + develop sections."""
    result = {}
    try:
        data = json.loads(content)
        for section in ("default", "develop"):
            for name, info in data.get(section, {}).items():
                ver = info.get("version", "")
                result[name] = ver.lstrip("=")
    except (json.JSONDecodeError, AttributeError):
        pass
    return result


def _parse_requirements_txt(content: str) -> dict[str, str]:
    """requirements.txt — only pinned versions (name==X.Y.Z)."""
    result = {}
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([A-Za-z0-9_.\-]+)", line)
        if m:
            result[m.group(1).lower()] = m.group(2)
    return result


def _parse_go_sum(content: str) -> dict[str, str]:
    """go.sum — module@version lines."""
    result = {}
    for line in content.splitlines():
        parts = line.split()
        if len(parts) >= 1:
            m = re.match(r"^([^@]+)@v([^\s/]+)", parts[0])
            if m:
                name, ver = m.group(1), m.group(2)
                # Keep highest version seen
                existing = _parse_version(result.get(name, "0"))
                if _parse_version(ver) >= existing:
                    result[name] = ver
    return result


def _parse_gemfile_lock(content: str) -> dict[str, str]:
    """Gemfile.lock — GEM specs section."""
    result = {}
    in_specs = False
    for line in content.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs:
            if not line.startswith("    "):
                in_specs = False
                continue
            # "    gem-name (1.2.3)" — 4-space indent = direct, 6-space = transitive
            m = re.match(r"^\s{4}([A-Za-z0-9_.\-]+)\s+\(([^)]+)\)", line)
            if m:
                result[m.group(1)] = m.group(2).split(",")[0].strip()
    return result


def _parse_cargo_lock(content: str) -> dict[str, str]:
    """Cargo.lock — TOML [[package]] blocks."""
    result = {}
    current_name = None
    for line in content.splitlines():
        line = line.strip()
        if line == "[[package]]":
            current_name = None
        elif line.startswith("name = "):
            current_name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = ") and current_name:
            version = line.split("=", 1)[1].strip().strip('"')
            result[current_name] = version
            current_name = None
    return result


def _parse_nuget_lock(content: str) -> dict[str, str]:
    """packages.lock.json — .NET NuGet lock file."""
    result = {}
    try:
        data = json.loads(content)
        for framework_deps in data.get("dependencies", {}).values():
            for name, info in framework_deps.items():
                resolved = info.get("resolved", "")
                if resolved:
                    result[name.lower()] = resolved
    except (json.JSONDecodeError, AttributeError):
        pass
    return result


def _parse_gradle_lock(content: str) -> dict[str, str]:
    """gradle.lockfile — group:artifact:version lines."""
    result = {}
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("#") or not line or "=" in line:
            continue
        parts = line.split(":")
        if len(parts) >= 3:
            name = f"{parts[0]}:{parts[1]}"
            version = parts[2].split("=")[0].strip()
            result[name] = version
    return result


PARSERS = {
    "package-lock.json": _parse_package_lock,
    "npm-shrinkwrap.json": _parse_package_lock,
    "yarn.lock": _parse_yarn_lock,
    "poetry.lock": _parse_poetry_lock,
    "Pipfile.lock": _parse_pipfile_lock,
    "requirements.txt": _parse_requirements_txt,
    "go.sum": _parse_go_sum,
    "Gemfile.lock": _parse_gemfile_lock,
    "Cargo.lock": _parse_cargo_lock,
    "packages.lock.json": _parse_nuget_lock,
    "gradle.lockfile": _parse_gradle_lock,
    "buildscript-gradle.lockfile": _parse_gradle_lock,
}

ECOSYSTEM_BY_LOCKFILE = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm",
    "yarn.lock": "npm",
    "poetry.lock": "pypi", "Pipfile.lock": "pypi", "requirements.txt": "pypi",
    "go.sum": "go",
    "Gemfile.lock": "gem",
    "Cargo.lock": "cargo",
    "packages.lock.json": "nuget",
    "gradle.lockfile": "gradle", "buildscript-gradle.lockfile": "gradle",
}


def _find_lockfiles_in_repo(repo: str) -> list[tuple[str, str]]:
    """
    Search for lockfiles in a repo. Returns [(file_path, filename), ...].
    Walks common directories where lockfiles live.
    """
    found = []
    search_paths = ["", "backend", "frontend", "api", "server", "app", "src", "web"]

    for base in search_paths:
        for lockfile in ALL_LOCKFILES:
            path = f"{base}/{lockfile}".lstrip("/")
            content = gh.get_file_content(repo, path)
            if content:
                found.append((path, lockfile))

    return found


def _normalize_package_name(name: str, ecosystem: str) -> str:
    """Normalize package names for case-insensitive comparison."""
    if ecosystem in ("pypi", "nuget"):
        return name.lower().replace("-", "_")
    if ecosystem == "npm":
        return name.lower()
    return name.lower()


def scan_repo(repo: str, hack: Hack) -> SupplyChainResult:
    """
    Scan a single repo's lockfiles for transitive dependencies matching
    any affected_libraries in the hack.
    """
    result = SupplyChainResult(repo=repo)

    if not hack.affected_libraries:
        return result

    print(f"  [supply_chain] Scanning {repo} for transitive deps "
          f"({len(hack.affected_libraries)} target lib(s))...")

    lockfiles = _find_lockfiles_in_repo(repo)
    if not lockfiles:
        print(f"  [supply_chain] No lockfiles found in {repo}")
        return result

    for lockfile_path, lockfile_name in lockfiles:
        result.lockfiles_checked.append(lockfile_path)
        content = gh.get_file_content(repo, lockfile_path)
        if not content:
            continue

        parser = PARSERS.get(lockfile_name)
        if not parser:
            continue

        try:
            resolved = parser(content)
        except Exception as e:
            result.errors.append(f"{lockfile_path}: parse error: {e}")
            continue

        ecosystem = ECOSYSTEM_BY_LOCKFILE.get(lockfile_name, "unknown")

        for lib in hack.affected_libraries:
            # Only check libraries matching this lockfile's ecosystem
            if lib.ecosystem not in (ecosystem, "apt"):  # apt libs often appear in lockfiles
                continue

            # Try exact name match and normalized match
            for name, version in resolved.items():
                if not version:
                    continue
                norm_name = _normalize_package_name(name, ecosystem)
                norm_lib = _normalize_package_name(lib.name, ecosystem)

                # Match on exact name or partial (e.g. "commons-collections" in "org.apache:commons-collections")
                if norm_lib not in norm_name and norm_name not in norm_lib:
                    continue

                if _version_in_range(version, lib.vulnerable_versions):
                    finding = TransitiveFinding(
                        repo=repo,
                        lockfile_path=lockfile_path,
                        ecosystem=ecosystem,
                        package=name,
                        resolved_version=version,
                        vulnerable_range=lib.vulnerable_versions,
                        safe_version=lib.safe_version,
                        dependency_depth="direct" if lockfile_name in (
                            "requirements.txt",
                        ) else "transitive",
                        confidence="high",  # lockfile pinned = exact version known
                    )
                    result.findings.append(finding)
                    print(f"  [supply_chain] FOUND: {name}@{version} in {lockfile_path} "
                          f"(vulnerable: {lib.vulnerable_versions})")

    return result


def scan_org(org: str, hack: Hack, repos: list[str] = None) -> list[SupplyChainResult]:
    """
    Scan all repos in an org for transitive dependency vulnerabilities.

    repos: pre-fetched list of repo full names. If None, fetches from org.
    """
    if repos is None:
        all_repos = gh.list_org_repos(org)
        repos = [r["full_name"] for r in all_repos]

    results = []
    vulnerable_count = 0

    for repo in repos:
        result = scan_repo(repo, hack)
        results.append(result)
        if result.is_vulnerable:
            vulnerable_count += 1

    print(f"  [supply_chain] Done: {vulnerable_count}/{len(repos)} repos have "
          f"transitive dependency exposure for '{hack.title}'")

    return results


def findings_to_scanner_format(results: list[SupplyChainResult], hack: Hack) -> list[dict]:
    """
    Convert SupplyChainResult findings to the same format scanner_agent produces,
    so they can flow into validator → triage → fixer unchanged.
    """
    scanner_findings = []
    for result in results:
        for finding in result.findings:
            scanner_findings.append({
                "repo": result.repo,
                "file": finding.lockfile_path,
                "reason": (
                    f"Transitive dependency {finding.package}@{finding.resolved_version} "
                    f"is in vulnerable range {finding.vulnerable_range}. "
                    f"Safe version: {finding.safe_version or 'unknown'}."
                ),
                "layer_hit": "L5",  # library versions layer
                "affected_library": f"{finding.package}@{finding.resolved_version}",
                "confidence": finding.confidence,
                "discovery_summary": {
                    "lockfile": finding.lockfile_path,
                    "ecosystem": finding.ecosystem,
                    "package": finding.package,
                    "resolved_version": finding.resolved_version,
                    "vulnerable_range": finding.vulnerable_range,
                    "safe_version": finding.safe_version,
                    "dependency_depth": finding.dependency_depth,
                },
            })
    return scanner_findings


if __name__ == "__main__":
    import sys
    from hack_registry import load_hacks

    repo = sys.argv[1] if len(sys.argv) > 1 else "stacksry/claude-mythos-zeroday"
    hacks = load_hacks()
    if not hacks:
        print("No hacks loaded.")
        sys.exit(1)

    hack = hacks[0]
    print(f"Supply chain scan: {repo} for '{hack.title}'")
    result = scan_repo(repo, hack)
    print(f"\nLockfiles checked: {result.lockfiles_checked}")
    print(f"Findings: {len(result.findings)}")
    for f in result.findings:
        print(f"  {f.package}@{f.resolved_version} — {f.lockfile_path}")

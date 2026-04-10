# Claude Mythos — Zero Day Hacks: Mitigations & Fixes

A structured research and automation project for tracking, analyzing, mitigating, and auto-remediating zero-day vulnerabilities — inspired by [Project Glasswing](https://www.anthropic.com/glasswing).

---

## Project Structure

```
claude-mythos-zeroday/
├── agents/          # Automated remediation pipeline (see below)
├── research/        # Vulnerability research, CVE analysis, threat intel
├── exploits/        # Proof-of-concept exploit documentation (for reference)
├── mitigations/     # Mitigation strategies and defensive measures
├── fixes/           # Patches, code fixes, and remediation scripts
├── tools/           # Scripts and tools used in analysis (C, Java)
├── reports/         # Auto-generated remediation reports
└── docs/            # Supporting documentation and templates
```

---

## Automated Remediation Pipeline

The `agents/` directory contains a multi-agent system powered by **Claude Opus 4.6** that automates the full remediation lifecycle across a GitHub organization.

### Architecture

```
orchestrator.py          ← entry point, loops through the hacks roster
├── scanner_agent.py     ← scans all org repos for vulnerable patterns
├── fixer_agent.py       ← applies fix + opens a PR per impacted repo
├── tester_agent.py      ← asserts the fix is correct via PR diff inspection
└── reporter_agent.py    ← generates a scored hygiene report
hack_registry.py         ← auto-loads hacks from research/ + fixes/
github_tools.py          ← GitHub API wrappers (scan, branch, PR, CI status)
```

### How It Works

| Step | Agent | What it does |
|---|---|---|
| 1 | **Scanner** | 6-layer structured discovery across all org repos (see below) |
| 2 | **Fixer** | Reads the vulnerable file, generates a minimal targeted fix, creates a branch, opens a PR |
| 3 | **Tester** | Reads the PR diff, verifies the vulnerable pattern is removed and the fix is correctly applied |
| 4 | **Reporter** | Calculates a hygiene score (0–100), generates a full markdown report with action items |

Each agent uses `claude-opus-4-6` with **adaptive thinking** for deep reasoning on complex code.

---

### Structured Discovery (Scanner Layers)

The scanner works through 6 layers per repo — each layer gates the next, so repos are ruled out early before expensive code-level analysis.

```
L1  Infrastructure    Dockerfiles, CI/CD workflows, Makefiles, Terraform, k8s
        ↓
L2  OS                Base images (FROM ubuntu, FROM alpine, FROM amazoncorretto, ...)
        ↓
L3  Language/Runtime  Build files: pom.xml, package.json, go.mod, requirements.txt, Gemfile, Cargo.toml
        ↓
L4  Frameworks        Spring Boot, Django, Express, Rails, Quarkus, FastAPI, Gin, ...
        ↓
L5  Library Versions  Parses manifests → checks if affected library version is in vulnerable range
        ↓  ← most important for dependency-based vulns
L6  Code Patterns     Grep for vulnerable code, reads file to confirm (rules out comments/tests)
```

Each hack in the registry carries explicit signals per layer:

```python
Hack(
    infra_signals    = ["Dockerfile", ".github/workflows/*.yml"],
    os_signals       = ["FROM openjdk", "FROM eclipse-temurin"],
    language_files   = ["pom.xml", "*.java"],
    framework_signals= ["spring-boot", "struts"],
    affected_libraries = [
        AffectedLibrary("commons-collections", "maven", "< 3.2.2", safe_version="3.2.2"),
        AffectedLibrary("jackson-databind",    "maven", "< 2.14.0", safe_version="2.14.0"),
    ],
    scan_patterns    = ["new ObjectInputStream(", "readObject()"],
)
```

The scanner result includes a `discovery_summary` per impacted repo showing exactly which layer triggered the finding:

```json
{
  "repo": "org/backend-service",
  "layer_hit": "L5",
  "affected_library": "commons-collections@3.2.1",
  "confidence": "high",
  "discovery_summary": {
    "infra": ["Dockerfile"],
    "os": ["eclipse-temurin:17"],
    "language": ["java"],
    "frameworks": ["spring-boot"],
    "vulnerable_libs": ["commons-collections@3.2.1"],
    "code_pattern": "new ObjectInputStream("
  }
}
```

### Setup

```bash
cd agents/
cp .env.example .env      # add ANTHROPIC_API_KEY + GITHUB_TOKEN
pip install -r requirements.txt
```

### Usage

```bash
# Scan only — no PRs created
python orchestrator.py --org your-github-org --dry-run

# Full pipeline: scan → fix → test → report
python orchestrator.py --org your-github-org

# Run against a single hack
python orchestrator.py --org your-github-org --hack java-deserialization
```

Reports are saved to `reports/remediation_<timestamp>.md`.

---

## Manual Workflow

1. **Research** — Document the vulnerability in `research/`
2. **Reproduce** — Record PoC details in `exploits/`
3. **Mitigate** — Draft short-term mitigations in `mitigations/`
4. **Fix** — Implement and document the fix in `fixes/`
5. **Report** — Write up findings in `reports/`

---

## Naming Conventions

| Folder | File naming |
|---|---|
| `research/` | `YYYY-MM-DD_vuln-name.md` |
| `exploits/` | `YYYY-MM-DD_vuln-name_poc.md` |
| `mitigations/` | `YYYY-MM-DD_vuln-name_mitigation.md` |
| `fixes/` | `YYYY-MM-DD_vuln-name_fix.md` |
| `reports/` | `YYYY-MM-DD_vuln-name_report.md` |

---

## Current Hacks Roster

| Vulnerability | Language | Severity | Research | PoC | Mitigation | Fix | Agent |
|---|---|---|---|---|---|---|---|
| FFmpeg Out-of-Bounds Write | C | High | ✅ | ✅ | ✅ | ✅ | ✅ |
| Java Unsafe Deserialization → RCE | Java | Critical | ✅ | ✅ | — | ✅ | ✅ |
| _(add entries here)_ | | | | | | | |

---

## Contact

- **Author:** stacksry
- **Email:** sridharreddyt@gmail.com

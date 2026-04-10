# System Architecture — Glasswing Agentic Remediation Platform

**Author:** stacksry
**Role:** Principal Engineer
**Reference:** [Claude Mythos Preview — red.anthropic.com](https://red.anthropic.com/2026/mythos-preview/)

---

## Gap Analysis: Current State vs. Mythos Expectations

### What Mythos Does (from the blog)

| Capability | Mythos Approach |
|---|---|
| File prioritization | Ranking agent scores every file 1–5 before any analysis |
| Parallelization | Multiple agents run concurrently on different files |
| Noise filtering | Secondary validation agent confirms each bug report |
| Human triage | Professional triagers review high-severity findings before vendor disclosure |
| Exploit validation | Containerized sandbox executes PoCs to confirm exploitability |
| Responsible disclosure | 90-day timeline, SHA-3 commitment hashes, structured vendor notification |
| Vulnerability classes | 8+ distinct classes (memory safety, logic bugs, web/app, firmware, system) |
| Scale | Thousands of findings; ~99% unpatched at disclosure time |

### What Our Current System Has

| Capability | Current State | Gap |
|---|---|---|
| File prioritization | None — flat scan | **Missing** |
| Parallelization | Sequential only | **Missing** |
| Noise filtering | None | **Missing** |
| Human triage | None | **Missing** |
| Exploit validation | Static code analysis only | **Missing** |
| Responsible disclosure | None | **Missing** |
| Vulnerability classes | 2 (OOB write, Java deserialization) | **Incomplete** |
| Scale | Manual, one-at-a-time | **Missing** |

---

## Redesigned Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ORCHESTRATOR (async)                         │
│              Processes hacks in parallel via asyncio                │
│              Priority queue: Critical → High → Medium → Low         │
│              --workers N for surge mode                             │
└──────────┬──────────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 1: DISCOVERY                                                 │
│                                                                     │
│  ┌─────────────────┐    ┌──────────────────────────────────────┐   │
│  │  ranker_agent   │    │        scanner_agent (parallel)      │   │
│  │                 │    │                                      │   │
│  │  Scores files   │───▶│  L1 Infra → L2 OS → L3 Lang →       │   │
│  │  1–5 on vuln    │    │  L4 Framework → L5 Lib Versions →   │   │
│  │  likelihood     │    │  L6 Code Patterns                   │   │
│  │  before scan    │    │                                      │   │
│  └─────────────────┘    │  Multiple instances run in parallel  │   │
│                         │  (one per file batch / repo)         │   │
│                         └──────────────────────────────────────┘   │
│                                        │                           │
│  ┌──────────────────────────────────┐  │                           │
│  │     supply_chain_agent          │  │                           │
│  │                                  │  │                           │
│  │  Parses lockfiles (poetry.lock,  │──┤  Runs in parallel with    │
│  │  package-lock.json, go.sum,      │  │  scanner_agent            │
│  │  Cargo.lock, Gemfile.lock, ...)  │  │                           │
│  │  Checks full transitive dep tree │  │                           │
│  │  — finds vulns 3 levels deep     │  │                           │
│  └──────────────────────────────────┘  │                           │
│                                        ▼                           │
│                         ┌──────────────────────────────────────┐   │
│                         │       validator_agent                │   │
│                         │                                      │   │
│                         │  Secondary noise filter — confirms   │   │
│                         │  each finding is real + exploitable  │   │
│                         └──────────────────────────────────────┘   │
│                                        │                           │
│                                        ▼                           │
│                         ┌──────────────────────────────────────┐   │
│                         │       sandbox_agent                  │   │
│                         │                                      │   │
│                         │  Structural exploit confirmation:    │   │
│                         │  1. Claude generates minimal PoC     │   │
│                         │  2. Runs in isolated Docker          │   │
│                         │     (--network none, --memory 256m,  │   │
│                         │      --read-only, 30s timeout)       │   │
│                         │  3. ASan/sanitizer output parsed     │   │
│                         │  Verdicts: CONFIRMED_EXPLOITABLE /   │   │
│                         │           NOT_REPRODUCIBLE /         │   │
│                         │           SANDBOX_ERROR              │   │
│                         └──────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 2: TRIAGE + ALERT                                            │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                     triage_agent                             │  │
│  │                                                              │  │
│  │  Severity assessment (CVSS v3.1) → routes by severity:      │  │
│  │                                                              │  │
│  │  Critical ──▶ human_review queue ──▶ alert_agent            │  │
│  │  High     ──▶ human_review + alert ──▶ auto-fix pipeline    │  │
│  │  Medium   ──▶ auto-fix pipeline (batched)                   │  │
│  │  Low      ──▶ backlog tracker                               │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                     alert_agent                              │  │
│  │                                                              │  │
│  │  Fires on human_review queue findings:                       │  │
│  │  → Slack  (SLACK_WEBHOOK_URL)                               │  │
│  │  → Email  (SMTP_HOST + ALERT_EMAIL_TO)                      │  │
│  │  → PagerDuty (PAGERDUTY_ROUTING_KEY) — Critical/High only   │  │
│  │  Logs to reports/alerts/{finding_id}_alert.json             │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 3: REMEDIATION                                               │
│                                                                     │
│  ┌─────────────────┐    ┌─────────────────┐    ┌────────────────┐  │
│  │  fixer_agent    │───▶│  tester_agent   │───▶│ reporter_agent │  │
│  │                 │    │                 │    │                │  │
│  │  Applies fix,   │    │  Validates fix  │    │ Hygiene score  │  │
│  │  opens PR       │    │  via PR diff +  │    │ + full report  │  │
│  │                 │    │  CI status      │    │                │  │
│  └─────────────────┘    └─────────────────┘    └────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 4: DISCLOSURE                                                │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                   disclosure_agent                           │  │
│  │                                                              │  │
│  │  - SHA-3 commitment hash at discovery time                   │  │
│  │  - 90-day countdown timer per finding                        │  │
│  │  - Generates vendor notification (CVE draft)                 │  │
│  │  - Tracks patch status → public disclosure trigger           │  │
│  │  - Escalation if vendor unresponsive after 45 days           │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Agent Responsibilities

### `supply_chain_agent.py` ← NEW
Scans the **full transitive dependency tree** — not just direct dependencies.

Parses 11 lockfile formats: `package-lock.json`, `yarn.lock`, `poetry.lock`, `Pipfile.lock`,
`requirements.txt`, `go.sum`, `Gemfile.lock`, `Cargo.lock`, `packages.lock.json`,
`gradle.lockfile`. Checks resolved versions against `affected_libraries` ranges using
semver comparison. Produces findings in scanner format so they flow into
validator → triage → fixer unchanged. Runs in parallel with the scanner in the orchestrator.

**Why:** 60–70% of real-world vulnerable dependency exposure is transitive, not direct.
A repo's `pom.xml` may not list `commons-collections` directly — it's pulled in 3 levels
deep via `spring-boot → hibernate → commons-collections@3.2.1`.

---

### `sandbox_agent.py` ← NEW
Structural exploit confirmation via isolated Docker containers. Eliminates the ~11%
false-positive gap that remains after the validator's reasoning-based check.

Flow:
1. Claude generates a minimal, self-contained PoC for the vulnerability
2. PoC is written to a temp dir and mounted into Docker
   (`--network none`, `--memory 256m`, `--cpus 0.5`, `--read-only`, 30s timeout)
3. Output is parsed for crash indicators (ASan errors, uncaught exceptions, panics)
4. Verdict: CONFIRMED_EXPLOITABLE → continues to triage; NOT_REPRODUCIBLE → dropped

Graceful degradation: if Docker is unavailable, returns SANDBOX_ERROR and the finding
continues through the pipeline (never silently drops findings).

---

### `alert_agent.py` ← NEW
Fires human review notifications for Critical and High findings.

| Channel | Config | Trigger |
|---|---|---|
| Slack | `SLACK_WEBHOOK_URL` | All human_review findings |
| Email | `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS`, `ALERT_EMAIL_TO` | All human_review findings |
| PagerDuty | `PAGERDUTY_ROUTING_KEY` | Critical + High only |

Each channel is attempted independently. Logs results to `reports/alerts/{finding_id}_alert.json`.

---

### `ranker_agent.py` ← NEW
Scores every file in a repo 1–5 on vulnerability likelihood **before** the scanner runs.
This mirrors Mythos's approach of prioritizing high-value files to maximize signal.

| Score | Meaning | Example files |
|---|---|---|
| 5 | Very likely — handles untrusted input, auth, crypto | `AuthController.java`, `tls_handshake.c`, `nfs_server.c` |
| 4 | Likely — network data, file parsing, memory management | `HttpParser.java`, `codec.c`, `deserialize.py` |
| 3 | Possible — internal logic with edge cases | `UserService.java`, `config_parser.c` |
| 2 | Unlikely — output only, UI, logging | `Logger.java`, `formatter.py` |
| 1 | Skip — tests, docs, generated code | `*Test.java`, `*.md`, `generated/` |

Only files scored 3–5 are passed to the scanner. This cuts noise and enables parallelization across high-priority files.

---

### `scanner_agent.py` ← ENHANCED (parallel instances)
Runs concurrently — one instance per file batch ranked 3+.
Now covers all 8 vulnerability classes from Mythos:

| Class | Examples |
|---|---|
| Memory safety | Stack overflow, use-after-free, OOB read/write, heap corruption |
| Logic bugs | Auth bypass, KASLR leak, protocol gap, crypto verification flaw |
| Code weaknesses | Missing bounds check, integer overflow, unsafe pointer arithmetic |
| Web/app | CSRF, SQLi, account takeover, auth bypass, DoS |
| System/kernel | LPE via race condition, NFS RCE, hypervisor escape |
| Firmware | JIT exploitation, hardware interaction |

---

### `validator_agent.py` ← NEW
Secondary noise filter — mirrors Mythos's validation step.
Prompt: *"I received this bug report. Is it real and exploitable in a realistic attack scenario?"*
Filters out:
- False positives (pattern matches in comments/tests)
- Low-impact findings (affects <0.1% of configurations)
- Already-patched or mitigated issues

---

### `triage_agent.py` ← NEW
CVSS-based severity scoring + routing.
Routes Critical findings to human review queue.
Generates structured triage record for every confirmed finding.

---

### `disclosure_agent.py` ← NEW
Full responsible disclosure lifecycle:
1. SHA-3 hash on discovery (timestamped commitment)
2. 90-day countdown per finding
3. Vendor notification drafts (CVE-ready format)
4. 45-day escalation if no response
5. Public disclosure brief on day 90

---

### `orchestrator.py` ← REWRITTEN (async/parallel)
Uses `asyncio` to run scanner instances in parallel.
Implements a priority queue — Critical/High processed first.
Supports surge mode: scale to N parallel workers when volume spikes.

---

## Vulnerability Class Registry

The `hack_registry.py` now covers all classes Mythos identified:

```
vuln_classes/
├── memory_safety/
│   ├── stack_overflow.py
│   ├── use_after_free.py
│   ├── oob_read_write.py      ← existing (FFmpeg)
│   └── heap_corruption.py
├── logic_bugs/
│   ├── auth_bypass.py
│   ├── kaslr_leak.py
│   ├── protocol_impl_gap.py
│   └── crypto_verification.py
├── code_weaknesses/
│   ├── missing_bounds_check.py
│   ├── integer_overflow.py
│   └── unsafe_pointer.py
├── web_app/
│   ├── deserialization_rce.py  ← existing (Java)
│   ├── sql_injection.py
│   ├── csrf.py
│   └── auth_bypass.py
└── system/
    ├── nfs_rce.py
    ├── lpe_race_condition.py
    └── hypervisor_escape.py
```

---

## Data Flow

```
Hack Registry
    │
    ▼
[Ranker] → ranks files 1-5
    │
    ▼
[Scanner ×N] ← parallel per file batch
    │
    ▼
[Validator] → noise filter
    │
    ▼
[Triage] → severity + routing
    │
    ├── Critical → human_queue + disclosure_agent
    ├── High     → fixer_agent → tester_agent
    └── Low/Med  → backlog + reporter_agent
    │
    ▼
[Reporter] → hygiene score, status table, action items
    │
    ▼
[Disclosure] → SHA-3 hash, 90-day timer, vendor notify
```

---

## Key Design Principles (from Mythos learnings)

1. **Parallelization is not optional.** Sequential scanning cannot scale to thousands of vulns. Every file batch above rank 3 gets its own agent instance.

2. **Always validate before disclosing.** The secondary validator prevents vendor fatigue from false positives. Mythos achieved 89% exact severity agreement with human triagers.

3. **Hard barriers > friction-based mitigations.** When generating fixes, prefer code isolation, type safety, and whitelist filters over rate limits or logging. Friction-based defenses degrade against AI-assisted attackers.

4. **Responsible disclosure is non-negotiable.** SHA-3 commitment hash at time of discovery, 90-day countdown, vendor notification, public brief on day 90.

5. **Triage at the gate.** Route Critical findings to humans immediately — do not auto-fix Critical severity without human sign-off.

6. **Patch cycles must compress.** A fix sitting in a PR for 30 days is not a fix. The reporter tracks time-to-merge, not just time-to-PR.

---

## Metrics to Track

| Metric | Target |
|---|---|
| Time to detection (TTD) | < 24h per repo scan |
| Time to PR (TTP) | < 4h after confirmed finding |
| Time to merge (TTM) | < 72h (requires org policy) |
| False positive rate | < 11% (Mythos benchmark) |
| Severity accuracy | > 89% exact, > 98% within 1 level |
| Patch coverage | % of confirmed findings with merged fix |
| Disclosure compliance | 100% within 90-day window |

"""
triage_agent.py

CVSS-based severity triage + routing after validation.
Routes findings to the correct downstream pipeline:

  Critical → human_review queue (alert) + disclosure_agent immediately
  High     → auto-fix pipeline
  Medium   → auto-fix pipeline (batched, lower priority)
  Low      → backlog tracker

Also generates a structured triage record for every confirmed finding,
matching the format used for responsible disclosure and reporting.
"""

import json
import hashlib
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path
import anthropic
from hack_registry import Hack
import memory_agent as mem


MODEL = "claude-opus-4-6"
TRIAGE_DIR = Path(__file__).parent.parent / "reports" / "triage"


@dataclass
class TriageRecord:
    finding_id: str                # SHA-3 of repo+file+hack_id+timestamp
    hack_id: str
    hack_title: str
    repo: str
    file: str
    severity: str                  # Critical | High | Medium | Low
    cvss_score: float
    cvss_vector: str
    route: str                     # human_review | auto_fix | backlog
    discovery_ts: str              # ISO8601
    disclosure_deadline: str       # 90 days from discovery
    exploitation_path: str
    population_impact: str
    affected_library: Optional[str] = None
    validation_confidence: float = 0.0
    notes: str = ""
    status: str = "open"           # open | in_fix | fixed | disclosed


def _finding_id(repo: str, file: str, hack_id: str) -> str:
    """Generate a SHA-3 commitment hash for this finding."""
    raw = f"{repo}|{file}|{hack_id}|{time.time_ns()}"
    return hashlib.sha3_256(raw.encode()).hexdigest()[:16]


def _disclosure_deadline(from_ts: str) -> str:
    """90 days from discovery timestamp."""
    from datetime import timedelta
    dt = datetime.fromisoformat(from_ts)
    return (dt + timedelta(days=90)).isoformat()


def _route(severity: str, needs_human: bool = False) -> str:
    if needs_human or severity == "Critical":
        return "human_review"
    if severity == "High":
        return "auto_fix"
    if severity == "Medium":
        return "auto_fix_batched"
    return "backlog"


CVSS_SYSTEM = """You are a CVSS v3.1 scoring expert. Given a security finding, return a
CVSS base score and vector string.

Consider:
- Attack Vector (Network/Adjacent/Local/Physical)
- Attack Complexity (Low/High)
- Privileges Required (None/Low/High)
- User Interaction (None/Required)
- Scope (Unchanged/Changed)
- Confidentiality/Integrity/Availability impact (None/Low/High)

Return JSON: {"score": 7.5, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}"""


def _score_cvss(finding: dict, hack: Hack) -> tuple[float, str]:
    """Ask Claude to generate a CVSS score for a finding."""
    client = anthropic.Anthropic()

    # ── Read memory: inject CVSS correction examples ──────────────────────────
    cvss_examples = mem.get_cvss_examples(hack.id)
    system = CVSS_SYSTEM + cvss_examples if cvss_examples else CVSS_SYSTEM

    prompt = (
        f"Vulnerability: {hack.title}\n"
        f"Severity label: {finding.get('severity', hack.severity)}\n"
        f"Exploitation path: {finding.get('validation', {}).get('exploitation_path', 'unknown')}\n"
        f"Population impact: {finding.get('validation', {}).get('population_impact', 'unknown')}\n"
        f"Affected library: {finding.get('affected_library', 'N/A')}\n"
        f"Layer hit: {finding.get('layer_hit', 'N/A')}\n\n"
        "Provide the CVSS v3.1 base score and vector."
    )
    response = client.messages.create(
        model=MODEL,
        max_tokens=256,
        system=system,
        messages=[{"role": "user", "content": prompt}],
    )
    for block in response.content:
        if block.type == "text":
            text = block.text.strip()
            try:
                start = text.index("{")
                end = text.rindex("}") + 1
                data = json.loads(text[start:end])
                return float(data.get("score", 0)), data.get("vector", "")
            except (ValueError, json.JSONDecodeError):
                pass
    # Fallback scores by severity label
    fallbacks = {"Critical": (9.0, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
                 "High": (7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
                 "Medium": (5.0, "AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N"),
                 "Low": (2.0, "AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")}
    sev = finding.get("severity", hack.severity)
    return fallbacks.get(sev, (5.0, ""))


def triage(finding: dict, hack: Hack) -> TriageRecord:
    """
    Triage a validated finding: score it, route it, generate a triage record.
    """
    severity = finding.get("severity", hack.severity)
    needs_human = finding.get("needs_human_review", False)
    validation = finding.get("validation", {})

    cvss_score, cvss_vector = _score_cvss(finding, hack)
    discovery_ts = datetime.now(timezone.utc).isoformat()
    finding_id = _finding_id(finding.get("repo", ""), finding.get("file", ""), hack.id)
    route = _route(severity, needs_human)

    record = TriageRecord(
        finding_id=finding_id,
        hack_id=hack.id,
        hack_title=hack.title,
        repo=finding.get("repo", ""),
        file=finding.get("file", ""),
        severity=severity,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        route=route,
        discovery_ts=discovery_ts,
        disclosure_deadline=_disclosure_deadline(discovery_ts),
        exploitation_path=validation.get("exploitation_path", "unknown"),
        population_impact=validation.get("population_impact", "unknown"),
        affected_library=finding.get("affected_library"),
        validation_confidence=validation.get("confidence", 0.0),
        notes=validation.get("reasoning", ""),
    )

    # Persist triage record
    TRIAGE_DIR.mkdir(parents=True, exist_ok=True)
    record_path = TRIAGE_DIR / f"{finding_id}.json"
    record_path.write_text(json.dumps(asdict(record), indent=2))

    # ── Write memory: ranker calibration if file was ranked below severity ────
    ranked_score = finding.get("ranked_score")
    if ranked_score is not None:
        file_path = finding.get("file", "")
        file_ext = "." + file_path.rsplit(".", 1)[-1] if "." in file_path else ""
        mem.record_ranker_calibration(
            file_path=file_path,
            file_extension=file_ext,
            ranked_score=int(ranked_score),
            actual_severity=severity,
            hack_id=hack.id,
            lesson=(
                f"{hack.title} found in {file_path} — "
                f"this file type ({file_ext}) should score higher for {hack.id}"
            ),
        )

    return record


def triage_batch(findings: list[dict], hack: Hack) -> dict[str, list]:
    """
    Triage a batch of validated findings.
    Returns: {human_review: [], auto_fix: [], auto_fix_batched: [], backlog: []}
    """
    queues: dict[str, list] = {
        "human_review": [],
        "auto_fix": [],
        "auto_fix_batched": [],
        "backlog": [],
    }

    for finding in findings:
        record = triage(finding, hack)
        print(f"  [triage] {record.repo}/{record.file} "
              f"→ {record.route} (CVSS {record.cvss_score}, {record.severity})")
        queues[record.route].append((finding, record))

    return queues


def load_open_records() -> list[TriageRecord]:
    """Load all open triage records for the disclosure agent."""
    records = []
    if not TRIAGE_DIR.exists():
        return []
    for f in TRIAGE_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text())
            records.append(TriageRecord(**data))
        except Exception:
            pass
    return [r for r in records if r.status == "open"]

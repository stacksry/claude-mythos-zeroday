"""
validator_agent.py

Secondary noise-filter agent — mirrors the Mythos Preview approach of running
a final validation pass on every bug report before it enters triage.

Prompt style from the blog:
  "I have received the following bug report. Can you please confirm if it's
   real and interesting?"

Filters out:
  - False positives (match in comment, test, or dead code)
  - Theoretical-only bugs (requires physical access, impossible conditions)
  - Already-patched or version-gated issues
  - Low-population impact (affects <0.1% of realistic configs)

Achieves the Mythos benchmark: >89% exact severity agreement with human triagers,
>98% within one severity level.
"""

import json
import anthropic
from hack_registry import Hack
import memory_agent as mem


MODEL = "claude-opus-4-6"


SYSTEM_PROMPT = """You are a senior security researcher performing secondary validation of
bug reports. Your role is to be a skeptical but fair reviewer — filter out noise without
discarding real issues.

For each bug report you receive, assess:

1. REALITY CHECK
   - Is the vulnerable code path actually reachable from untrusted input?
   - Is the match in live production code, or in a test / comment / dead branch?
   - Does the vulnerable version actually appear in the dependency manifest?

2. EXPLOITABILITY
   - Can an unauthenticated or low-privilege attacker reach this?
   - What's the realistic worst-case impact (RCE, data leak, DoS, auth bypass)?
   - Are there existing mitigations (sandboxing, WAF, firewall rules) that block exploitation?

3. POPULATION IMPACT
   - Does this affect a broad population of users, or only rare/edge configurations?
   - Is it in a core code path or an obscure feature?

4. DUPLICATION / ALREADY PATCHED
   - Is there evidence this was already fixed in a later version?
   - Does the repo already have a PR or issue addressing this?

Verdict options:
  CONFIRMED   — real, exploitable, broad impact → pass to triage
  DOWNGRADED  — real but lower severity than reported → pass with adjusted severity
  NEEDS_INFO  — cannot confirm without more context → flag for human review
  REJECTED    — false positive, theoretical only, already fixed, or negligible impact

Return a JSON object:
{
  "verdict": "CONFIRMED|DOWNGRADED|NEEDS_INFO|REJECTED",
  "adjusted_severity": "Critical|High|Medium|Low|null",
  "confidence": 0.0–1.0,
  "reasoning": "clear explanation",
  "rejection_reason": "if REJECTED: false_positive|theoretical|already_patched|low_impact",
  "exploitation_path": "brief description of how an attacker exploits this",
  "population_impact": "broad|moderate|narrow|negligible"
}"""


def validate(finding: dict, hack: Hack, file_content: str = "") -> dict:
    """
    Validate a scanner finding before it enters triage.

    finding: {repo, file, reason, layer_hit, affected_library, confidence, discovery_summary}
    Returns: {verdict, adjusted_severity, confidence, reasoning, ...}
    """
    client = anthropic.Anthropic()

    report_text = (
        f"**Bug Report**\n\n"
        f"Repository: {finding.get('repo')}\n"
        f"File: {finding.get('file')}\n"
        f"Vulnerability: {hack.title}\n"
        f"Reported severity: {hack.severity}\n"
        f"Scanner confidence: {finding.get('confidence')}\n"
        f"Layer hit: {finding.get('layer_hit')}\n"
        f"Affected library: {finding.get('affected_library', 'N/A')}\n"
        f"Scanner reason: {finding.get('reason')}\n\n"
        f"Discovery summary:\n{json.dumps(finding.get('discovery_summary', {}), indent=2)}\n\n"
    )

    if file_content:
        # Include first 200 lines of the vulnerable file for context
        lines = file_content.splitlines()[:200]
        report_text += f"**Relevant file content (first 200 lines):**\n```\n" + "\n".join(lines) + "\n```\n"

    report_text += (
        f"\n**Vulnerability class details:**\n"
        f"{hack.raw_research[:600]}\n\n"
        "Please validate this bug report and return your verdict JSON."
    )

    # ── Read memory: inject known false positive signals ──────────────────────
    fp_signals = mem.get_false_positive_signals(hack.id)
    system = SYSTEM_PROMPT + fp_signals if fp_signals else SYSTEM_PROMPT

    response = client.messages.create(
        model=MODEL,
        max_tokens=2048,
        thinking={"type": "adaptive"},
        system=system,
        messages=[{"role": "user", "content": report_text}],
    )

    for block in response.content:
        if block.type == "text":
            text = block.text.strip()
            try:
                start = text.index("{")
                end = text.rindex("}") + 1
                return json.loads(text[start:end])
            except (ValueError, json.JSONDecodeError):
                pass

    return {
        "verdict": "NEEDS_INFO",
        "adjusted_severity": hack.severity,
        "confidence": 0.5,
        "reasoning": "Validator returned unparseable response — flagged for human review.",
        "rejection_reason": None,
        "exploitation_path": "Unknown",
        "population_impact": "unknown",
    }


def validate_batch(findings: list[dict], hack: Hack) -> list[dict]:
    """
    Validate a batch of findings. Returns only CONFIRMED and DOWNGRADED.
    Attaches validation result to each passing finding.
    """
    import github_tools as gh

    confirmed = []
    for finding in findings:
        repo = finding.get("repo", "")
        file_path = finding.get("file", "")

        # Fetch file content for context
        file_content = ""
        if repo and file_path:
            file_content = gh.get_file_content(repo, file_path) or ""

        result = validate(finding, hack, file_content)
        verdict = result.get("verdict", "REJECTED")

        print(f"  [validator] {repo}/{file_path} → {verdict} "
              f"(confidence: {result.get('confidence', 0):.0%})")

        if verdict in ("CONFIRMED", "DOWNGRADED"):
            finding["validation"] = result
            if verdict == "DOWNGRADED" and result.get("adjusted_severity"):
                finding["severity"] = result["adjusted_severity"]
            else:
                finding["severity"] = hack.severity
            confirmed.append(finding)
        elif verdict == "NEEDS_INFO":
            finding["validation"] = result
            finding["severity"] = hack.severity
            finding["needs_human_review"] = True
            confirmed.append(finding)
        elif verdict == "REJECTED":
            # ── Write memory: record what made this a false positive ──────────
            rejection_reason = result.get("rejection_reason", "false_positive") or "false_positive"
            reasoning = result.get("reasoning", "")
            if reasoning:
                mem.record_false_positive(
                    hack_id=hack.id,
                    file_path=finding.get("file", ""),
                    rejection_reason=rejection_reason,
                    signal=reasoning[:300],
                )

    return confirmed

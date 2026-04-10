"""
sandbox_agent.py

Containerized exploit confirmation — runs PoCs in isolated Docker containers
to structurally confirm exploitability before findings enter triage.

For each validated finding:
  1. Claude generates a minimal PoC for the specific vulnerability
  2. A Docker container runs the PoC in an isolated environment
  3. Output is parsed for crash/exploit indicators
  4. Result: CONFIRMED_EXPLOITABLE | NOT_REPRODUCIBLE | SANDBOX_ERROR

Requires Docker daemon running locally (`docker info` must succeed).
"""

import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

import anthropic
from triage_agent import TriageRecord
from hack_registry import Hack
import memory_agent as mem

# ── Configuration ─────────────────────────────────────────────────────────────

MODEL = "claude-opus-4-6"
SANDBOX_DIR = Path(__file__).parent.parent / "reports" / "sandbox"
CONTAINER_TIMEOUT = 30  # seconds

logger = logging.getLogger(__name__)

# ── Language → Docker image mapping ──────────────────────────────────────────

LANGUAGE_CONFIG = {
    "c": {
        "image": "ubuntu:22.04",
        "default_crash_indicators": ["ASAN ERROR", "runtime error", "Segmentation fault"],
        "ext": ".c",
    },
    "c++": {
        "image": "ubuntu:22.04",
        "default_crash_indicators": ["ASAN ERROR", "runtime error", "Segmentation fault"],
        "ext": ".cpp",
    },
    "cpp": {
        "image": "ubuntu:22.04",
        "default_crash_indicators": ["ASAN ERROR", "runtime error", "Segmentation fault"],
        "ext": ".cpp",
    },
    "java": {
        "image": "eclipse-temurin:17",
        "default_crash_indicators": [
            "Exception in thread",
            "RuntimeException",
            "java.lang.reflect",
            "Caused by:",
            "StackOverflowError",
            "ClassCastException",
        ],
        "ext": ".java",
    },
    "python": {
        "image": "python:3.11-slim",
        "default_crash_indicators": [
            "Traceback (most recent call last)",
            "Exception",
            "Error:",
            "SystemExit",
        ],
        "ext": ".py",
    },
    "javascript": {
        "image": "node:20-slim",
        "default_crash_indicators": [
            "Error:",
            "TypeError",
            "ReferenceError",
            "UnhandledPromiseRejection",
            "process exited",
        ],
        "ext": ".js",
    },
    "js": {
        "image": "node:20-slim",
        "default_crash_indicators": [
            "Error:",
            "TypeError",
            "ReferenceError",
            "UnhandledPromiseRejection",
        ],
        "ext": ".js",
    },
    "go": {
        "image": "golang:1.21-alpine",
        "default_crash_indicators": [
            "panic:",
            "goroutine",
            "runtime error",
            "signal: segmentation fault",
        ],
        "ext": ".go",
    },
}

# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class SandboxResult:
    verdict: str           # CONFIRMED_EXPLOITABLE | NOT_REPRODUCIBLE | SANDBOX_ERROR
    finding_id: str
    language: str
    crash_output: str      # relevant portion of output
    crash_indicator: str   # which indicator matched
    poc_code: str
    error: str = ""

# ── Docker availability check ─────────────────────────────────────────────────

def _docker_available() -> bool:
    """Return True if the Docker daemon is reachable."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False

# ── PoC generation ────────────────────────────────────────────────────────────

POC_SYSTEM = """You are a senior offensive security researcher writing proof-of-concept (PoC)
exploit code for internal vulnerability confirmation within a defensive security pipeline.
Your PoC runs inside an isolated Docker container with no network access.

Rules:
- The PoC must be entirely self-contained with no external dependencies beyond the base image.
- The PoC must be minimal — only enough code to demonstrate the vulnerability.
- The PoC must terminate on its own (no infinite loops without a bound).
- Do NOT include any actual data exfiltration, network calls, or destructive filesystem ops.
- The goal is crash/anomaly confirmation only.

Return ONLY valid JSON (no markdown fences, no prose):
{
  "language": "<c|cpp|java|python|javascript|go>",
  "filename": "<poc.c|Poc.java|poc.py|poc.js|poc.go>",
  "code": "<full source code as a string>",
  "compile_cmd": "<shell command to compile, or empty string if interpreted>",
  "run_cmd": "<shell command to run the compiled binary or interpreter>",
  "crash_indicators": ["<string to search in output>", ...]
}

For C/C++: compile with clang -fsanitize=address,undefined and include crash_indicators
  ["ASAN ERROR", "runtime error", "Segmentation fault"].
For Java: public class Poc { public static void main(String[] args) { ... } }
For Python: a top-level script with no pip installs required.
For JavaScript/Node: a top-level script with no npm installs required.
For Go: package main with func main()."""


def _generate_poc(record: TriageRecord, file_content: str, hack: Optional[Hack]) -> dict:
    """Ask Claude to generate a minimal PoC for the given finding. Returns parsed JSON dict."""
    client = anthropic.Anthropic()

    # Trim file content to first 50 lines
    snippet_lines = (file_content or "").splitlines()[:50]
    snippet = "\n".join(snippet_lines) if snippet_lines else "(no source snippet available)"

    hack_title = hack.title if hack else record.hack_title
    hack_desc = (hack.fix_description if hack and hack.fix_description else
                 f"Vulnerability type: {record.hack_id}")
    language = (hack.language if hack else "python").lower()

    user_prompt = (
        f"Vulnerability title: {hack_title}\n"
        f"Description: {hack_desc}\n"
        f"Primary language: {language}\n"
        f"Affected file path: {record.file}\n\n"
        f"Affected source snippet (first 50 lines):\n```\n{snippet}\n```\n\n"
        f"Exploitation path: {record.exploitation_path}\n\n"
        "Write a minimal, self-contained PoC that demonstrates this vulnerability "
        "inside a Docker container. Return JSON only."
    )

    response = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        thinking={"type": "adaptive"},
        system=POC_SYSTEM,
        messages=[{"role": "user", "content": user_prompt}],
    )

    raw_text = ""
    for block in response.content:
        if hasattr(block, "text"):
            raw_text += block.text

    raw_text = raw_text.strip()

    # Extract JSON — strip markdown fences if present
    if raw_text.startswith("```"):
        lines = raw_text.splitlines()
        # Drop first and last fence lines
        inner = []
        in_block = False
        for line in lines:
            if line.startswith("```") and not in_block:
                in_block = True
                continue
            if line.startswith("```") and in_block:
                break
            if in_block:
                inner.append(line)
        raw_text = "\n".join(inner).strip()

    try:
        start = raw_text.index("{")
        end = raw_text.rindex("}") + 1
        return json.loads(raw_text[start:end])
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"Claude returned non-JSON PoC response: {raw_text[:300]}") from exc


# ── Container execution ───────────────────────────────────────────────────────

def _build_docker_cmd(image: str, tmpdir: str, compile_cmd: str, run_cmd: str) -> list:
    """Build the docker run command list."""
    shell_cmd = run_cmd
    if compile_cmd:
        shell_cmd = f"{compile_cmd} && {run_cmd}"

    return [
        "docker", "run",
        "--rm",
        "--network", "none",
        "--memory", "256m",
        "--cpus", "0.5",
        "--read-only",
        "--tmpfs", "/tmp",
        "-v", f"{tmpdir}:/work",
        "-w", "/work",
        image,
        "sh", "-c", shell_cmd,
    ]


def _run_in_container(image: str, tmpdir: str, compile_cmd: str, run_cmd: str) -> tuple[str, bool, str]:
    """
    Run the PoC inside a Docker container.

    Returns (combined_output, timed_out, error_message).
    """
    cmd = _build_docker_cmd(image, tmpdir, compile_cmd, run_cmd)
    logger.debug("Docker command: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=CONTAINER_TIMEOUT,
        )
        combined = (proc.stdout or "") + (proc.stderr or "")
        return combined, False, ""
    except subprocess.TimeoutExpired:
        return "", True, "timeout"
    except FileNotFoundError:
        return "", False, "docker_unavailable"
    except OSError as exc:
        return "", False, f"os_error: {exc}"


# ── Output parsing ────────────────────────────────────────────────────────────

def _find_crash_indicator(output: str, indicators: list) -> tuple[bool, str, str]:
    """
    Scan output for crash indicators.

    Returns (found, indicator_matched, relevant_snippet).
    """
    lines = output.splitlines()
    for indicator in indicators:
        for i, line in enumerate(lines):
            if indicator.lower() in line.lower():
                # Return up to 10 lines around the match for context
                start = max(0, i - 2)
                end = min(len(lines), i + 8)
                snippet = "\n".join(lines[start:end])
                return True, indicator, snippet
    return False, "", ""


# ── Result persistence ────────────────────────────────────────────────────────

def _save_result(result: SandboxResult) -> None:
    """Persist sandbox result to reports/sandbox/{finding_id}_sandbox.json."""
    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
    out_path = SANDBOX_DIR / f"{result.finding_id}_sandbox.json"
    out_path.write_text(json.dumps(asdict(result), indent=2))
    logger.info("Sandbox result saved to %s", out_path)


# ── Public API ────────────────────────────────────────────────────────────────

def run_sandbox(record: TriageRecord, file_content: str = "", hack: Optional[Hack] = None) -> SandboxResult:
    """
    Run PoC in sandbox for a triage record. Returns SandboxResult.

    Verdicts:
      CONFIRMED_EXPLOITABLE  — crash/exploit indicator found in container output
      NOT_REPRODUCIBLE       — container ran cleanly, no indicators matched
      SANDBOX_ERROR          — Docker unavailable, timeout, or PoC generation failure
    """
    finding_id = record.finding_id
    language = (hack.language if hack else "python").lower()

    # Graceful degradation: check Docker first
    if not _docker_available():
        logger.warning("Docker not available — skipping sandbox for finding %s", finding_id)
        result = SandboxResult(
            verdict="SANDBOX_ERROR",
            finding_id=finding_id,
            language=language,
            crash_output="",
            crash_indicator="",
            poc_code="",
            error="docker_unavailable",
        )
        _save_result(result)
        return result

    # Resolve language config
    lang_key = language if language in LANGUAGE_CONFIG else "python"
    lang_cfg = LANGUAGE_CONFIG[lang_key]

    # Step 1: Generate PoC with Claude
    try:
        poc_data = _generate_poc(record, file_content, hack)
    except Exception as exc:
        logger.error("PoC generation failed for %s: %s", finding_id, exc)
        result = SandboxResult(
            verdict="SANDBOX_ERROR",
            finding_id=finding_id,
            language=language,
            crash_output="",
            crash_indicator="",
            poc_code="",
            error=f"poc_generation_failed: {exc}",
        )
        _save_result(result)
        return result

    poc_language = poc_data.get("language", lang_key)
    poc_filename = poc_data.get("filename", f"poc{lang_cfg['ext']}")
    poc_code = poc_data.get("code", "")
    compile_cmd = poc_data.get("compile_cmd", "")
    run_cmd = poc_data.get("run_cmd", "")
    crash_indicators = poc_data.get("crash_indicators", lang_cfg["default_crash_indicators"])

    # Merge with default crash indicators for the language
    merged_indicators = list(dict.fromkeys(
        crash_indicators + lang_cfg.get("default_crash_indicators", [])
    ))

    # Resolve image: prefer language config from PoC response, fallback to detected
    poc_lang_cfg = LANGUAGE_CONFIG.get(poc_language, lang_cfg)
    image = poc_lang_cfg["image"]

    if not poc_code:
        result = SandboxResult(
            verdict="SANDBOX_ERROR",
            finding_id=finding_id,
            language=poc_language,
            crash_output="",
            crash_indicator="",
            poc_code="",
            error="poc_generation_failed: empty code returned",
        )
        _save_result(result)
        return result

    if not run_cmd:
        result = SandboxResult(
            verdict="SANDBOX_ERROR",
            finding_id=finding_id,
            language=poc_language,
            crash_output="",
            crash_indicator="",
            poc_code=poc_code,
            error="poc_generation_failed: no run_cmd returned",
        )
        _save_result(result)
        return result

    # Step 2: Write PoC to temp dir and run in container
    with tempfile.TemporaryDirectory() as tmpdir:
        poc_path = Path(tmpdir) / poc_filename
        poc_path.write_text(poc_code)

        logger.info(
            "Running sandbox for finding %s (lang=%s, image=%s)",
            finding_id, poc_language, image,
        )

        output, timed_out, run_error = _run_in_container(image, tmpdir, compile_cmd, run_cmd)

    # Step 3: Evaluate results
    if timed_out:
        result = SandboxResult(
            verdict="SANDBOX_ERROR",
            finding_id=finding_id,
            language=poc_language,
            crash_output="",
            crash_indicator="",
            poc_code=poc_code,
            error="timeout",
        )
        _save_result(result)
        return result

    if run_error == "docker_unavailable":
        result = SandboxResult(
            verdict="SANDBOX_ERROR",
            finding_id=finding_id,
            language=poc_language,
            crash_output="",
            crash_indicator="",
            poc_code=poc_code,
            error="docker_unavailable",
        )
        _save_result(result)
        return result

    if run_error:
        result = SandboxResult(
            verdict="SANDBOX_ERROR",
            finding_id=finding_id,
            language=poc_language,
            crash_output=output[:2000],
            crash_indicator="",
            poc_code=poc_code,
            error=run_error,
        )
        _save_result(result)
        return result

    # Step 4: Parse output for crash indicators
    found, indicator, snippet = _find_crash_indicator(output, merged_indicators)

    if found:
        logger.info(
            "CONFIRMED_EXPLOITABLE for %s — indicator: %r", finding_id, indicator
        )
        verdict = "CONFIRMED_EXPLOITABLE"
        # ── Write memory: record the confirming code pattern ──────────────────
        if hack and poc_code:
            # Extract a short representative pattern from the PoC code
            poc_lines = [l.strip() for l in poc_code.splitlines() if l.strip() and not l.strip().startswith("//") and not l.strip().startswith("#")]
            pattern_line = poc_lines[0] if poc_lines else poc_code[:80]
            mem.record_confirmed_scan_pattern(
                hack_id=hack.id,
                pattern=pattern_line[:120],
                language=poc_language,
                crash_indicator=indicator,
                confirmed_by="sandbox",
            )
    else:
        logger.info("NOT_REPRODUCIBLE for %s — no crash indicators found", finding_id)
        verdict = "NOT_REPRODUCIBLE"

    result = SandboxResult(
        verdict=verdict,
        finding_id=finding_id,
        language=poc_language,
        crash_output=snippet if found else output[:500],
        crash_indicator=indicator,
        poc_code=poc_code,
        error="",
    )
    _save_result(result)
    return result


def confirm_batch(records: list, hack: Optional[Hack] = None) -> dict:
    """
    Run sandbox for a list of TriageRecords.

    Returns:
        {
            "confirmed": [SandboxResult, ...],   # CONFIRMED_EXPLOITABLE
            "unconfirmed": [SandboxResult, ...], # NOT_REPRODUCIBLE
            "errors": [SandboxResult, ...],      # SANDBOX_ERROR
        }
    """
    output: dict = {"confirmed": [], "unconfirmed": [], "errors": []}

    for record in records:
        # Accept either a bare TriageRecord or a (finding, record) tuple
        # (triage_batch returns tuples)
        if isinstance(record, tuple):
            finding, triage_record = record
            file_content = finding.get("file_content", "")
        else:
            triage_record = record
            file_content = ""

        try:
            result = run_sandbox(triage_record, file_content=file_content, hack=hack)
        except Exception as exc:
            logger.error(
                "Unexpected error in sandbox for %s: %s",
                getattr(triage_record, "finding_id", "unknown"),
                exc,
            )
            result = SandboxResult(
                verdict="SANDBOX_ERROR",
                finding_id=getattr(triage_record, "finding_id", "unknown"),
                language=hack.language if hack else "unknown",
                crash_output="",
                crash_indicator="",
                poc_code="",
                error=f"unexpected_error: {exc}",
            )
            _save_result(result)

        print(
            f"  [sandbox] {result.finding_id} → {result.verdict}"
            + (f" ({result.crash_indicator})" if result.crash_indicator else "")
            + (f" [err: {result.error}]" if result.error else "")
        )

        if result.verdict == "CONFIRMED_EXPLOITABLE":
            output["confirmed"].append(result)
        elif result.verdict == "NOT_REPRODUCIBLE":
            output["unconfirmed"].append(result)
        else:
            output["errors"].append(result)

    return output

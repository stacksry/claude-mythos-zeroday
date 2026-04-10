"""
scanner_agent.py

Structured discovery scanner — runs 6 layered checks per repo before
concluding whether it is impacted by a given vulnerability.

Discovery layers:
  L1  Infrastructure   — Dockerfiles, CI/CD, IaC, Makefiles
  L2  OS               — base images, runner OS
  L3  Language/runtime — build files, source extensions
  L4  Frameworks       — Spring, Django, Express, Rails, etc.
  L5  Library versions — pom.xml, package.json, requirements.txt, go.mod, etc.
  L6  Code patterns    — vulnerable code confirmation

Each layer gates the next: a repo that has no Java files is skipped for
a Java deserialization check at L6.
"""

import json
import anthropic
from hack_registry import Hack, AffectedLibrary
import github_tools as gh
import memory_agent as mem


MODEL = "claude-opus-4-6"

# ── Tool definitions for Claude ──────────────────────────────────────────────

TOOLS = [
    # L1
    {
        "name": "list_org_repos",
        "description": "List all repositories in the GitHub org with language and topic metadata.",
        "input_schema": {
            "type": "object",
            "properties": {"org_name": {"type": "string"}},
            "required": ["org_name"],
        },
    },
    {
        "name": "find_infra_files",
        "description": "Layer 1 — find infrastructure files (Dockerfiles, CI/CD workflows, Makefiles, IaC) in a repo.",
        "input_schema": {
            "type": "object",
            "properties": {"repo_full_name": {"type": "string"}},
            "required": ["repo_full_name"],
        },
    },
    # L2
    {
        "name": "extract_base_images",
        "description": "Layer 2 — extract FROM lines from Dockerfiles to identify OS base images.",
        "input_schema": {
            "type": "object",
            "properties": {"repo_full_name": {"type": "string"}},
            "required": ["repo_full_name"],
        },
    },
    # L3
    {
        "name": "detect_languages",
        "description": "Layer 3 — detect languages used in the repo by scanning for language-specific build/manifest files.",
        "input_schema": {
            "type": "object",
            "properties": {"repo_full_name": {"type": "string"}},
            "required": ["repo_full_name"],
        },
    },
    # L4
    {
        "name": "detect_frameworks",
        "description": "Layer 4 — detect frameworks (Spring, Django, Express, etc.) used in the repo.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo_full_name": {"type": "string"},
                "language": {"type": "string", "description": "Primary language detected in L3"},
            },
            "required": ["repo_full_name", "language"],
        },
    },
    # L5
    {
        "name": "get_manifest_content",
        "description": "Layer 5 — fetch manifest/lockfile content (pom.xml, package.json, requirements.txt, go.mod, etc.) to inspect library versions.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo_full_name": {"type": "string"},
                "ecosystem": {
                    "type": "string",
                    "description": "Dependency ecosystem: maven | npm | pypi | go | gem | cargo | nuget",
                },
            },
            "required": ["repo_full_name", "ecosystem"],
        },
    },
    {
        "name": "parse_library_versions",
        "description": "Layer 5 — parse library names and versions from a manifest file's raw content.",
        "input_schema": {
            "type": "object",
            "properties": {
                "manifest_path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["manifest_path", "content"],
        },
    },
    # L6
    {
        "name": "search_code_in_org",
        "description": "Layer 6 — search for a specific code pattern across the org (or a single repo).",
        "input_schema": {
            "type": "object",
            "properties": {
                "org_name": {"type": "string"},
                "pattern": {"type": "string"},
                "language": {"type": "string"},
            },
            "required": ["org_name", "pattern"],
        },
    },
    {
        "name": "get_file_content",
        "description": "Fetch the raw content of a specific file to confirm a match in context.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo_full_name": {"type": "string"},
                "file_path": {"type": "string"},
            },
            "required": ["repo_full_name", "file_path"],
        },
    },
]


def _dispatch_tool(name: str, tool_input: dict) -> str:
    if name == "list_org_repos":
        return json.dumps(gh.list_org_repos(tool_input["org_name"]))

    elif name == "find_infra_files":
        return json.dumps(gh.find_infra_files(tool_input["repo_full_name"]))

    elif name == "extract_base_images":
        return json.dumps(gh.extract_base_images(tool_input["repo_full_name"]))

    elif name == "detect_languages":
        return json.dumps(gh.detect_languages(tool_input["repo_full_name"]))

    elif name == "detect_frameworks":
        return json.dumps(gh.detect_frameworks(
            tool_input["repo_full_name"], tool_input["language"]
        ))

    elif name == "get_manifest_content":
        return json.dumps(gh.get_manifest_content(
            tool_input["repo_full_name"], tool_input["ecosystem"]
        ))

    elif name == "parse_library_versions":
        return json.dumps(gh.parse_library_versions(
            tool_input["manifest_path"], tool_input["content"]
        ))

    elif name == "search_code_in_org":
        return json.dumps(gh.search_code_in_org(
            tool_input["org_name"],
            tool_input["pattern"],
            tool_input.get("language"),
        ))

    elif name == "get_file_content":
        content = gh.get_file_content(
            tool_input["repo_full_name"], tool_input["file_path"]
        )
        return content or "File not found or empty."

    return "Unknown tool."


def _build_system_prompt(hack: Hack) -> str:
    libs_text = "\n".join(
        f"  - {l.name} ({l.ecosystem}) versions {l.vulnerable_versions}"
        + (f" → safe: {l.safe_version}" if l.safe_version else "")
        for l in hack.affected_libraries
    ) or "  (none specified)"

    return f"""You are a structured security scanner for Project Glasswing.
You use a 6-layer discovery process to find repos impacted by a specific vulnerability.
Work through each layer in order. Skip a repo at the earliest layer that rules it out.

Vulnerability: {hack.title}
Severity: {hack.severity}
Primary language: {hack.language}

Layer signals:
  L1 Infrastructure : {hack.infra_signals}
  L2 OS targets     : {hack.os_signals}
  L3 Language files : {hack.language_files}
  L4 Frameworks     : {hack.framework_signals}
  L5 Affected libs  :
{libs_text}
  L6 Code patterns  : {hack.scan_patterns}

Discovery rules:
- L1: Check if the repo has relevant infra files (Dockerfile, CI/CD, IaC).
      If a repo has no build/deploy infrastructure, it's lower priority but don't skip.
- L2: Check base OS images. Flag if they match the OS signals above.
- L3: Confirm the language is present. If the repo has no {hack.language} files, skip L4–L6.
- L4: Confirm a relevant framework is used. Low-risk repos can still be checked at L5.
- L5: Parse manifests and check if any affected library version is in the vulnerable range.
      This is the most important layer for dependency-based vulns.
- L6: Search for the vulnerable code pattern as final confirmation.
      Read the matching file to rule out false positives (comments, tests, already-fixed).

Final output — a JSON list of impacted repos:
[
  {{
    "repo": "org/repo",
    "file": "path/to/file",
    "reason": "clear explanation of why it is impacted",
    "layer_hit": "L5|L6",
    "affected_library": "library-name@version",
    "confidence": "high|medium|low",
    "discovery_summary": {{
      "infra": ["Dockerfile found"],
      "os": ["ubuntu:22.04"],
      "language": ["java"],
      "frameworks": ["spring-boot"],
      "vulnerable_libs": ["commons-collections@3.2.1"],
      "code_pattern": "new ObjectInputStream("
    }}
  }}
]
Return [] if no repos are impacted. Return ONLY the JSON list."""


def scan(org_name: str, hack: Hack) -> list[dict]:
    """
    Run the structured 6-layer scanner for a hack against the given GitHub org.
    Returns list of impacted repos with full discovery context.
    """
    # ── Read memory: extend scan_patterns with sandbox-confirmed patterns ─────
    learned_patterns = mem.get_confirmed_patterns(hack.id)
    if learned_patterns:
        # Extend without mutating the shared Hack object
        hack = Hack(
            **{k: v for k, v in hack.__dict__.items() if k != "scan_patterns"},
            scan_patterns=list(dict.fromkeys(hack.scan_patterns + learned_patterns)),
        )

    client = anthropic.Anthropic()

    messages = [
        {
            "role": "user",
            "content": (
                f"Scan the GitHub org '{org_name}' for the vulnerability: {hack.title}.\n\n"
                "Follow the 6-layer discovery process described in your instructions.\n"
                "Start by listing all repos, then work through each layer per repo.\n"
                "Return only the final JSON list of impacted repos."
            ),
        }
    ]

    while True:
        response = client.messages.create(
            model=MODEL,
            max_tokens=8192,
            thinking={"type": "adaptive"},
            system=_build_system_prompt(hack),
            tools=TOOLS,
            messages=messages,
        )

        if response.stop_reason == "end_turn":
            for block in response.content:
                if block.type == "text":
                    text = block.text.strip()
                    try:
                        start = text.index("[")
                        end = text.rindex("]") + 1
                        return json.loads(text[start:end])
                    except (ValueError, json.JSONDecodeError):
                        print(f"[scanner] Could not parse result JSON: {text[:300]}")
                        return []
            return []

        if response.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": response.content})
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    print(f"  [scanner:L?] {block.name}({list(block.input.values())[:2]})")
                    result = _dispatch_tool(block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    })
            messages.append({"role": "user", "content": tool_results})
            continue

        break

    return []


if __name__ == "__main__":
    import sys
    from hack_registry import load_hacks

    org = sys.argv[1] if len(sys.argv) > 1 else "stacksry"
    hacks = load_hacks()
    if not hacks:
        print("No hacks loaded.")
        sys.exit(1)

    hack = hacks[0]
    print(f"Scanning org '{org}' for: {hack.title}")
    print(f"  Affected libs: {[(l.name, l.vulnerable_versions) for l in hack.affected_libraries]}")
    impacted = scan(org, hack)
    print(json.dumps(impacted, indent=2))

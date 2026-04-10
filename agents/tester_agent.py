"""
tester_agent.py

Validates that a fix was correctly applied in a PR.
Uses Claude to:
  1. Inspect the PR diff
  2. Verify the vulnerable pattern is removed
  3. Verify the fix pattern is present
  4. Check CI status if available
  5. Return a pass/fail verdict with reasoning
"""

import json
import anthropic
from hack_registry import Hack
import github_tools as gh


MODEL = "claude-opus-4-6"

TOOLS = [
    {
        "name": "get_pr_files",
        "description": "Get the list of files changed in a PR, including the diff patch.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo_full_name": {"type": "string"},
                "pr_number": {"type": "integer"},
            },
            "required": ["repo_full_name", "pr_number"],
        },
    },
    {
        "name": "get_pr_status",
        "description": "Get the PR state and CI check results.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo_full_name": {"type": "string"},
                "pr_number": {"type": "integer"},
            },
            "required": ["repo_full_name", "pr_number"],
        },
    },
    {
        "name": "get_file_content",
        "description": "Fetch the content of a file on the fix branch to verify the fix.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo_full_name": {"type": "string"},
                "file_path": {"type": "string"},
                "ref": {"type": "string", "description": "Branch name or commit SHA"},
            },
            "required": ["repo_full_name", "file_path"],
        },
    },
]


def _dispatch_tool(name: str, tool_input: dict) -> str:
    if name == "get_pr_files":
        files = gh.get_pr_files(tool_input["repo_full_name"], tool_input["pr_number"])
        return json.dumps(files)
    elif name == "get_pr_status":
        status = gh.get_pr_status(tool_input["repo_full_name"], tool_input["pr_number"])
        return json.dumps(status)
    elif name == "get_file_content":
        content = gh.get_file_content(
            tool_input["repo_full_name"],
            tool_input["file_path"],
            tool_input.get("ref", "HEAD"),
        )
        return content or "File not found."
    return "Unknown tool."


def _extract_pr_number(pr_url: str) -> int | None:
    """Extract the PR number from a GitHub PR URL."""
    import re
    match = re.search(r"/pull/(\d+)$", pr_url)
    return int(match.group(1)) if match else None


def assert_fix(
    repo_full_name: str,
    pr_url: str,
    fix_branch: str,
    impacted_file: str,
    hack: Hack,
) -> dict:
    """
    Assert that the fix was correctly applied.
    Returns: {passed: bool, verdict: str, checks: list[str], ci_status: str}
    """
    pr_number = _extract_pr_number(pr_url)
    if not pr_number:
        return {
            "passed": False,
            "verdict": f"Could not parse PR number from URL: {pr_url}",
            "checks": [],
            "ci_status": "unknown",
        }

    client = anthropic.Anthropic()
    messages = [
        {
            "role": "user",
            "content": (
                f"You are a security code reviewer asserting that a fix was correctly applied.\n\n"
                f"**Vulnerability:** {hack.title}\n"
                f"**Repository:** {repo_full_name}\n"
                f"**PR number:** {pr_number}\n"
                f"**Fix branch:** {fix_branch}\n"
                f"**Patched file:** {impacted_file}\n\n"
                f"**What the fix should do:**\n{hack.fix_description}\n\n"
                f"**Vulnerable patterns that must be GONE:**\n"
                + "\n".join(f"  - `{p}`" for p in hack.scan_patterns)
                + "\n\n"
                "Instructions:\n"
                "1. Fetch the PR files to see the diff.\n"
                "2. Fetch the file content on the fix branch to read the full patched version.\n"
                "3. Check CI status.\n"
                "4. Verify:\n"
                "   a) The vulnerable pattern is no longer present in the patched file.\n"
                "   b) The fix was applied correctly (bounds check, filter, etc. is in place).\n"
                "   c) No unrelated code was changed.\n"
                "5. Return a JSON object:\n"
                '   {"passed": true/false, "verdict": "one paragraph explanation", '
                '"checks": ["check 1 passed", "check 2 failed", ...], "ci_status": "..."}\n'
                "Return ONLY the JSON object."
            ),
        }
    ]

    while True:
        response = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            thinking={"type": "adaptive"},
            tools=TOOLS,
            messages=messages,
        )

        if response.stop_reason == "end_turn":
            for block in response.content:
                if block.type == "text":
                    text = block.text.strip()
                    try:
                        start = text.index("{")
                        end = text.rindex("}") + 1
                        return json.loads(text[start:end])
                    except (ValueError, json.JSONDecodeError):
                        return {
                            "passed": False,
                            "verdict": f"Could not parse result: {text[:200]}",
                            "checks": [],
                            "ci_status": "unknown",
                        }
            return {"passed": False, "verdict": "No text block returned.", "checks": [], "ci_status": "unknown"}

        if response.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": response.content})
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result = _dispatch_tool(block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    })
            messages.append({"role": "user", "content": tool_results})
            continue

        break

    return {"passed": False, "verdict": "Unexpected stop.", "checks": [], "ci_status": "unknown"}

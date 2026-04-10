"""
scanner_agent.py

Scans all repos in a GitHub org for a given vulnerability pattern.
Uses Claude with tool use to reason about scan results and determine
which repos are genuinely impacted (vs. false positives).
"""

import json
import anthropic
from hack_registry import Hack
import github_tools as gh


MODEL = "claude-opus-4-6"

TOOLS = [
    {
        "name": "list_org_repos",
        "description": "List all repositories in the GitHub organization.",
        "input_schema": {
            "type": "object",
            "properties": {
                "org_name": {"type": "string", "description": "GitHub org name"}
            },
            "required": ["org_name"],
        },
    },
    {
        "name": "search_code_in_org",
        "description": "Search GitHub code for a vulnerability pattern in the org.",
        "input_schema": {
            "type": "object",
            "properties": {
                "org_name": {"type": "string"},
                "pattern": {"type": "string", "description": "Code pattern to search for"},
                "language": {"type": "string", "description": "Optional language filter (java, c, python, etc.)"},
            },
            "required": ["org_name", "pattern"],
        },
    },
    {
        "name": "get_file_content",
        "description": "Fetch the raw content of a specific file from a repo to inspect the context around a match.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo_full_name": {"type": "string", "description": "e.g. myorg/myrepo"},
                "file_path": {"type": "string"},
            },
            "required": ["repo_full_name", "file_path"],
        },
    },
]


def _dispatch_tool(name: str, tool_input: dict) -> str:
    if name == "list_org_repos":
        result = gh.list_org_repos(tool_input["org_name"])
        return json.dumps(result)
    elif name == "search_code_in_org":
        result = gh.search_code_in_org(
            tool_input["org_name"],
            tool_input["pattern"],
            tool_input.get("language"),
        )
        return json.dumps(result)
    elif name == "get_file_content":
        content = gh.get_file_content(
            tool_input["repo_full_name"],
            tool_input["file_path"],
        )
        return content or "File not found or empty."
    return "Unknown tool."


def scan(org_name: str, hack: Hack) -> list[dict]:
    """
    Run the scanner agent for a specific hack against the given GitHub org.
    Returns a list of impacted repos: [{repo, file, reason, confidence}]
    """
    client = anthropic.Anthropic()
    messages = [
        {
            "role": "user",
            "content": (
                f"You are a security scanner. Your task: find all repositories in the "
                f"GitHub org '{org_name}' that are vulnerable to the following:\n\n"
                f"**Vulnerability:** {hack.title}\n"
                f"**Severity:** {hack.severity}\n"
                f"**Language:** {hack.language}\n"
                f"**Known vulnerable patterns:**\n"
                + "\n".join(f"  - `{p}`" for p in hack.scan_patterns)
                + "\n\n"
                f"**Root cause summary:**\n{hack.raw_research[:800]}\n\n"
                "Instructions:\n"
                "1. List all org repos.\n"
                "2. Search for each vulnerability pattern.\n"
                "3. For each match, fetch the file to confirm it's a genuine use of "
                "   the vulnerable pattern (not a comment, test, or already-fixed code).\n"
                "4. Return a JSON list of impacted repos in this format:\n"
                '   [{"repo": "org/repo", "file": "path/to/file.java", '
                '"reason": "why it\'s impacted", "confidence": "high|medium|low"}]\n'
                "5. If no repos are impacted, return an empty list [].\n"
                "Return ONLY the JSON list as your final answer."
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
            # Extract the JSON list from the final text block
            for block in response.content:
                if block.type == "text":
                    text = block.text.strip()
                    try:
                        start = text.index("[")
                        end = text.rindex("]") + 1
                        return json.loads(text[start:end])
                    except (ValueError, json.JSONDecodeError):
                        print(f"[scanner] Could not parse JSON from: {text[:200]}")
                        return []
            return []

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

    return []


if __name__ == "__main__":
    import sys
    from hack_registry import load_hacks

    org = sys.argv[1] if len(sys.argv) > 1 else "stacksry"
    hacks = load_hacks()
    if not hacks:
        print("No hacks loaded. Add research docs first.")
        sys.exit(1)

    hack = hacks[0]
    print(f"Scanning org '{org}' for: {hack.title}")
    impacted = scan(org, hack)
    print(json.dumps(impacted, indent=2))

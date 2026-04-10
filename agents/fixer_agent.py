"""
fixer_agent.py

Applies the fix for a given vulnerability to an impacted repo.
Creates a branch and opens a PR with the remediation.
Uses Claude with tool use to generate the correct fix for the specific file.
"""

import json
import anthropic
from hack_registry import Hack
import github_tools as gh
import memory_agent as mem


MODEL = "claude-opus-4-6"

TOOLS = [
    {
        "name": "get_file_content",
        "description": "Fetch the full content of a file from the repo.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo_full_name": {"type": "string"},
                "file_path": {"type": "string"},
            },
            "required": ["repo_full_name", "file_path"],
        },
    },
    {
        "name": "create_branch",
        "description": "Create a new git branch in the repo for the fix.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo_full_name": {"type": "string"},
                "branch_name": {"type": "string"},
                "from_branch": {"type": "string", "description": "Base branch (default: main)"},
            },
            "required": ["repo_full_name", "branch_name"],
        },
    },
    {
        "name": "update_file",
        "description": "Update a file in the repo on the fix branch with the remediated content.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo_full_name": {"type": "string"},
                "file_path": {"type": "string"},
                "new_content": {"type": "string", "description": "Full new file content with fix applied"},
                "branch": {"type": "string"},
                "commit_message": {"type": "string"},
            },
            "required": ["repo_full_name", "file_path", "new_content", "branch", "commit_message"],
        },
    },
    {
        "name": "create_pull_request",
        "description": "Open a pull request with the fix.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo_full_name": {"type": "string"},
                "head_branch": {"type": "string"},
                "base_branch": {"type": "string"},
                "title": {"type": "string"},
                "body": {"type": "string", "description": "PR description with vulnerability details and fix explanation"},
            },
            "required": ["repo_full_name", "head_branch", "base_branch", "title", "body"],
        },
    },
]


def _dispatch_tool(name: str, tool_input: dict) -> str:
    if name == "get_file_content":
        content = gh.get_file_content(tool_input["repo_full_name"], tool_input["file_path"])
        return content or "File not found."
    elif name == "create_branch":
        success = gh.create_branch(
            tool_input["repo_full_name"],
            tool_input["branch_name"],
            tool_input.get("from_branch", "main"),
        )
        return "Branch created successfully." if success else "Failed to create branch."
    elif name == "update_file":
        success = gh.update_file(
            tool_input["repo_full_name"],
            tool_input["file_path"],
            tool_input["new_content"],
            tool_input["branch"],
            tool_input["commit_message"],
        )
        return "File updated successfully." if success else "Failed to update file."
    elif name == "create_pull_request":
        pr_url = gh.create_pull_request(
            tool_input["repo_full_name"],
            tool_input["head_branch"],
            tool_input["base_branch"],
            tool_input["title"],
            tool_input["body"],
        )
        return pr_url or "Failed to create PR."
    return "Unknown tool."


def apply_fix(repo_full_name: str, impacted_file: str, hack: Hack) -> dict:
    """
    Apply the fix for a hack to a specific file in a repo.
    Returns: {success: bool, pr_url: str, branch: str, notes: str}
    """
    client = anthropic.Anthropic()
    branch_name = f"glasswing/fix-{hack.id}"

    # ── Read memory: inject proven fix patterns from previous runs ────────────
    file_ext = "." + impacted_file.rsplit(".", 1)[-1] if "." in impacted_file else ""
    fix_examples = mem.get_fix_examples(hack.id, hack.language)

    messages = [
        {
            "role": "user",
            "content": (
                f"You are a security engineer applying a fix to a vulnerable file.\n\n"
                f"**Vulnerability:** {hack.title}\n"
                f"**Severity:** {hack.severity}\n"
                f"**Repository:** {repo_full_name}\n"
                f"**Vulnerable file:** {impacted_file}\n\n"
                f"**Fix strategy:**\n{hack.fix_description}\n\n"
                f"**Full fix reference:**\n{hack.raw_fix[:2000]}\n\n"
                + fix_examples +
                "\nInstructions:\n"
                f"1. Fetch the content of `{impacted_file}` from `{repo_full_name}`.\n"
                f"2. Create a new branch named `{branch_name}` (base: main).\n"
                "3. Apply the fix to the file content — make the minimal targeted change "
                "   that eliminates the vulnerability. Do NOT refactor unrelated code.\n"
                "   Prefer proven fix patterns above when they match the vulnerable code.\n"
                "4. Update the file on the fix branch with a clear commit message.\n"
                "5. Open a PR with:\n"
                f"   - title: `[Glasswing] Fix {hack.title} in {impacted_file}`\n"
                "   - body: explain what was changed and why, reference the vulnerability.\n"
                "6. Return a JSON object: "
                '{"success": true/false, "pr_url": "...", "branch": "...", '
                '"vulnerable_snippet": "...", "fix_snippet": "...", "notes": "..."}\n'
                "Include the key lines of vulnerable code and the fix in the JSON.\n"
                "Return ONLY the JSON object as your final answer."
            ),
        }
    ]

    while True:
        response = client.messages.create(
            model=MODEL,
            max_tokens=8192,
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
                        result = json.loads(text[start:end])
                        # ── Write memory: record fix pattern on success ────────
                        if result.get("success") and result.get("vulnerable_snippet") and result.get("fix_snippet"):
                            mem.record_fix_pattern(
                                hack_id=hack.id,
                                language=hack.language,
                                file_extension=file_ext,
                                vulnerable_snippet=result["vulnerable_snippet"],
                                fix_snippet=result["fix_snippet"],
                                repo=repo_full_name,
                                confirmed_by="fixer_agent",
                            )
                        return result
                    except (ValueError, json.JSONDecodeError):
                        return {"success": False, "pr_url": None, "branch": branch_name,
                                "notes": f"Could not parse result: {text[:200]}"}
            return {"success": False, "pr_url": None, "branch": branch_name, "notes": "No text block returned."}

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

    return {"success": False, "pr_url": None, "branch": branch_name, "notes": "Unexpected stop."}

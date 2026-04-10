"""
ranker_agent.py

Scores every file in a repo on a 1–5 vulnerability likelihood scale
BEFORE the scanner runs — mirrors the Mythos Preview approach of
prioritizing high-value files to maximize signal and enable parallelization.

Score meanings:
  5 — Very likely: handles untrusted input, auth, crypto, memory management
  4 — Likely: network data, file parsing, serialization, IPC
  3 — Possible: internal logic with edge cases, config handling
  2 — Unlikely: output-only, UI rendering, logging
  1 — Skip: tests, docs, generated code, vendored third-party

Only files scored >= MIN_SCORE are passed to the scanner.
"""

import json
import anthropic
import github_tools as gh
import memory_agent as mem


MODEL = "claude-opus-4-6"
MIN_SCORE = 3  # files below this are skipped


TOOLS = [
    {
        "name": "list_repo_files",
        "description": "List all file paths in a repo (up to 500 files).",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo_full_name": {"type": "string"},
                "path": {"type": "string", "description": "Directory path to list (default: root)"},
            },
            "required": ["repo_full_name"],
        },
    },
    {
        "name": "get_file_content",
        "description": "Fetch the content of a specific file to assess its vulnerability likelihood.",
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


def _list_repo_files(repo_full_name: str, path: str = "") -> list[str]:
    """Walk a repo and return all file paths."""
    import github_tools as gh
    from github import Github, GithubException
    import os

    g = gh.get_client()
    repo = g.get_repo(repo_full_name)
    files = []

    def _walk(p: str):
        try:
            contents = repo.get_contents(p)
            if not isinstance(contents, list):
                contents = [contents]
            for item in contents:
                if item.type == "file":
                    files.append(item.path)
                elif item.type == "dir" and len(files) < 500:
                    _walk(item.path)
        except GithubException:
            pass

    _walk(path)
    return files


def _dispatch_tool(name: str, tool_input: dict) -> str:
    if name == "list_repo_files":
        files = _list_repo_files(
            tool_input["repo_full_name"],
            tool_input.get("path", ""),
        )
        return json.dumps(files)
    elif name == "get_file_content":
        content = gh.get_file_content(
            tool_input["repo_full_name"],
            tool_input["file_path"],
        )
        # Truncate to first 100 lines for ranking (we don't need full content)
        if content:
            lines = content.splitlines()[:100]
            return "\n".join(lines)
        return "File not found or empty."
    return "Unknown tool."


SYSTEM_PROMPT = """You are a security-focused file ranker. Your job is to score every file in a
repository on a 1–5 vulnerability likelihood scale, so that a scanner agent can prioritize
the highest-risk files.

Scoring rubric:
  5 — Very high: handles untrusted external input, authentication, cryptography, memory
      allocation/deallocation, network protocol parsing, deserialization, privilege checks.
      Examples: AuthController, TlsHandshake, NfsServer, ObjectInputStream usage, malloc/free.

  4 — High: file parsing (XML, JSON, binary formats), IPC/RPC handlers, session management,
      database query construction, codec/compression, config loaders.

  3 — Medium: internal business logic with edge cases, data transformation, config parsing,
      background job runners.

  2 — Low: output formatting, UI rendering, logging, metrics, CLI argument parsing.

  1 — Skip: unit tests, integration tests, generated code, vendor/third-party, documentation,
      build scripts, migration files.

Instructions:
1. List all files in the repo.
2. For each file, apply the rubric using file name, path, and (for ambiguous cases) a peek
   at the first 100 lines of content.
3. Return a JSON array sorted by score descending:
   [{"path": "src/auth/AuthService.java", "score": 5, "reason": "handles login and session tokens"},
    {"path": "src/util/Logger.java", "score": 2, "reason": "output only, no input handling"},
    ...]
Return ONLY the JSON array."""


def rank(repo_full_name: str, vuln_language: str = "") -> list[dict]:
    """
    Rank all files in a repo by vulnerability likelihood.
    Returns list of {path, score, reason} sorted by score descending.
    """
    client = anthropic.Anthropic()

    # ── Read memory: inject ranker calibration examples ───────────────────────
    calibration_examples = mem.get_ranker_examples()
    system = SYSTEM_PROMPT + calibration_examples if calibration_examples else SYSTEM_PROMPT

    messages = [
        {
            "role": "user",
            "content": (
                f"Rank all files in `{repo_full_name}` by vulnerability likelihood.\n"
                + (f"Primary language context: {vuln_language}.\n" if vuln_language else "")
                + "Start by listing all files, then score each one. Return the JSON array."
            ),
        }
    ]

    while True:
        response = client.messages.create(
            model=MODEL,
            max_tokens=8192,
            system=system,
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
                        ranked = json.loads(text[start:end])
                        return sorted(ranked, key=lambda x: x.get("score", 0), reverse=True)
                    except (ValueError, json.JSONDecodeError):
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


def get_priority_files(repo_full_name: str, vuln_language: str = "", min_score: int = MIN_SCORE) -> list[dict]:
    """
    Return only files scoring >= min_score — the ones worth scanning.
    """
    all_files = rank(repo_full_name, vuln_language)
    return [f for f in all_files if f.get("score", 0) >= min_score]


if __name__ == "__main__":
    import sys
    repo = sys.argv[1] if len(sys.argv) > 1 else "stacksry/claude-mythos-zeroday"
    print(f"Ranking files in {repo}...")
    ranked = get_priority_files(repo)
    for f in ranked:
        print(f"  [{f['score']}] {f['path']} — {f.get('reason', '')}")

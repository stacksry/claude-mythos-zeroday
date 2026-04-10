"""
github_tools.py

GitHub API wrappers used by the scanner, fixer, and tester agents.
Wraps PyGitHub for clean agent tool interfaces.
"""

import base64
import os
from typing import Optional
from github import Github, GithubException


def get_client() -> Github:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise EnvironmentError("GITHUB_TOKEN environment variable not set.")
    return Github(token)


# ---------------------------------------------------------------------------
# Scanner tools
# ---------------------------------------------------------------------------

def list_org_repos(org_name: str) -> list[dict]:
    """List all repos in a GitHub org."""
    g = get_client()
    org = g.get_organization(org_name)
    return [
        {
            "name": repo.name,
            "full_name": repo.full_name,
            "language": repo.language,
            "url": repo.html_url,
            "default_branch": repo.default_branch,
        }
        for repo in org.get_repos()
    ]


def search_code_in_org(org_name: str, pattern: str, language: Optional[str] = None) -> list[dict]:
    """
    Search GitHub code for a pattern within an org.
    Returns list of {repo, path, url} matches.
    """
    g = get_client()
    query = f'org:{org_name} "{pattern}"'
    if language:
        query += f" language:{language}"

    results = []
    try:
        for result in g.search_code(query):
            results.append({
                "repo": result.repository.full_name,
                "path": result.path,
                "url": result.html_url,
                "sha": result.sha,
            })
    except GithubException as e:
        print(f"[github_tools] search_code error: {e}")

    return results


def get_file_content(repo_full_name: str, file_path: str, ref: str = "HEAD") -> Optional[str]:
    """Fetch raw content of a file from a repo."""
    g = get_client()
    try:
        repo = g.get_repo(repo_full_name)
        content = repo.get_contents(file_path, ref=ref)
        if isinstance(content, list):
            return None  # it's a directory
        return base64.b64decode(content.content).decode("utf-8", errors="replace")
    except GithubException as e:
        print(f"[github_tools] get_file_content error: {e}")
        return None


# ---------------------------------------------------------------------------
# Fixer tools
# ---------------------------------------------------------------------------

def create_branch(repo_full_name: str, branch_name: str, from_branch: str = "main") -> bool:
    """Create a new branch in a repo."""
    g = get_client()
    try:
        repo = g.get_repo(repo_full_name)
        source = repo.get_branch(from_branch)
        repo.create_git_ref(f"refs/heads/{branch_name}", source.commit.sha)
        return True
    except GithubException as e:
        print(f"[github_tools] create_branch error: {e}")
        return False


def update_file(
    repo_full_name: str,
    file_path: str,
    new_content: str,
    branch: str,
    commit_message: str,
) -> bool:
    """Update (or create) a file in a branch."""
    g = get_client()
    try:
        repo = g.get_repo(repo_full_name)
        try:
            existing = repo.get_contents(file_path, ref=branch)
            repo.update_file(
                file_path,
                commit_message,
                new_content,
                existing.sha,
                branch=branch,
            )
        except GithubException:
            # File doesn't exist yet — create it
            repo.create_file(file_path, commit_message, new_content, branch=branch)
        return True
    except GithubException as e:
        print(f"[github_tools] update_file error: {e}")
        return False


def create_pull_request(
    repo_full_name: str,
    head_branch: str,
    base_branch: str,
    title: str,
    body: str,
) -> Optional[str]:
    """Open a pull request. Returns the PR URL or None on failure."""
    g = get_client()
    try:
        repo = g.get_repo(repo_full_name)
        pr = repo.create_pull(
            title=title,
            body=body,
            head=head_branch,
            base=base_branch,
        )
        return pr.html_url
    except GithubException as e:
        print(f"[github_tools] create_pull_request error: {e}")
        return None


# ---------------------------------------------------------------------------
# Tester tools
# ---------------------------------------------------------------------------

def get_pr_files(repo_full_name: str, pr_number: int) -> list[dict]:
    """Get the list of files changed in a PR."""
    g = get_client()
    try:
        repo = g.get_repo(repo_full_name)
        pr = repo.get_pull(pr_number)
        return [
            {"filename": f.filename, "status": f.status, "additions": f.additions,
             "deletions": f.deletions, "patch": f.patch}
            for f in pr.get_files()
        ]
    except GithubException as e:
        print(f"[github_tools] get_pr_files error: {e}")
        return []


def get_pr_status(repo_full_name: str, pr_number: int) -> dict:
    """Get PR state and CI check results."""
    g = get_client()
    try:
        repo = g.get_repo(repo_full_name)
        pr = repo.get_pull(pr_number)
        commit = repo.get_commit(pr.head.sha)
        checks = [
            {"name": s.context, "state": s.state}
            for s in commit.get_statuses()
        ]
        return {
            "state": pr.state,
            "merged": pr.merged,
            "mergeable": pr.mergeable,
            "checks": checks,
        }
    except GithubException as e:
        print(f"[github_tools] get_pr_status error: {e}")
        return {}

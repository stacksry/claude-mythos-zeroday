"""
github_tools.py

GitHub API wrappers for the scanner, fixer, and tester agents.
Includes manifest fetching for structured discovery layers.
"""

import base64
import os
import re
from typing import Optional
from github import Github, GithubException


# Manifest files per ecosystem — used in Layer 5 (library version scanning)
MANIFEST_FILES = {
    "maven":  ["pom.xml", "build.gradle", "build.gradle.kts"],
    "npm":    ["package.json", "package-lock.json", "yarn.lock"],
    "pypi":   ["requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml", "setup.py"],
    "go":     ["go.mod", "go.sum"],
    "gem":    ["Gemfile", "Gemfile.lock"],
    "cargo":  ["Cargo.toml", "Cargo.lock"],
    "nuget":  ["*.csproj", "packages.config", "nuget.config"],
}

# Infrastructure files — used in Layer 1
INFRA_FILES = [
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".github/workflows",
    "terraform", "*.tf", "*.tfvars",
    "kubernetes", "k8s", "helm",
    "Makefile", "CMakeLists.txt",
    "ansible", "*.yml",
]


def get_client() -> Github:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise EnvironmentError("GITHUB_TOKEN environment variable not set.")
    return Github(token)


# ---------------------------------------------------------------------------
# Layer 1: Infrastructure discovery
# ---------------------------------------------------------------------------

def list_org_repos(org_name: str) -> list[dict]:
    """List all repos in a GitHub org with basic metadata."""
    g = get_client()
    org = g.get_organization(org_name)
    return [
        {
            "name": repo.name,
            "full_name": repo.full_name,
            "language": repo.language,
            "url": repo.html_url,
            "default_branch": repo.default_branch,
            "topics": list(repo.get_topics()),
            "size": repo.size,
        }
        for repo in org.get_repos()
    ]


def find_infra_files(repo_full_name: str) -> list[dict]:
    """
    Discover infrastructure files in a repo (Dockerfiles, CI/CD, IaC).
    Returns list of {path, type} entries.
    """
    g = get_client()
    repo = g.get_repo(repo_full_name)
    found = []

    def _walk(path: str = ""):
        try:
            contents = repo.get_contents(path)
            if not isinstance(contents, list):
                contents = [contents]
            for item in contents:
                name = item.name.lower()
                if any(kw in name for kw in
                       ["dockerfile", "docker-compose", ".tf", "makefile",
                        "cmake", "ansible", "helm", "k8s", "kubernetes"]):
                    found.append({"path": item.path, "type": "infra"})
                if item.path == ".github" or item.name in ("terraform", "k8s", "kubernetes", "helm"):
                    _walk(item.path)
        except GithubException:
            pass

    _walk()

    # Also check .github/workflows explicitly
    try:
        workflows = repo.get_contents(".github/workflows")
        if isinstance(workflows, list):
            for wf in workflows:
                found.append({"path": wf.path, "type": "ci_cd"})
    except GithubException:
        pass

    return found


# ---------------------------------------------------------------------------
# Layer 2: OS discovery
# ---------------------------------------------------------------------------

def extract_base_images(repo_full_name: str) -> list[dict]:
    """
    Find all FROM lines in Dockerfiles to identify base OS images.
    Returns list of {dockerfile, image, os_family}.
    """
    g = get_client()
    results = []
    try:
        for hit in g.search_code(f'repo:{repo_full_name} filename:Dockerfile FROM'):
            content = get_file_content(repo_full_name, hit.path)
            if content:
                for line in content.splitlines():
                    line = line.strip()
                    if line.upper().startswith("FROM") and not line.startswith("#"):
                        image = line.split()[1] if len(line.split()) > 1 else "unknown"
                        os_family = _classify_os(image)
                        results.append({
                            "dockerfile": hit.path,
                            "image": image,
                            "os_family": os_family,
                        })
    except GithubException:
        pass
    return results


def _classify_os(image: str) -> str:
    image = image.lower()
    if "alpine" in image:
        return "alpine"
    if "ubuntu" in image:
        return "ubuntu"
    if "debian" in image:
        return "debian"
    if "centos" in image or "rhel" in image or "ubi" in image:
        return "redhat"
    if "amazon" in image or "amazoncorretto" in image:
        return "amazon-linux"
    if "openjdk" in image or "eclipse-temurin" in image:
        return "jvm-image"
    if "node" in image:
        return "node-image"
    if "python" in image:
        return "python-image"
    if "scratch" in image:
        return "scratch"
    return "unknown"


# ---------------------------------------------------------------------------
# Layer 3: Language / runtime detection
# ---------------------------------------------------------------------------

def detect_languages(repo_full_name: str) -> dict[str, list[str]]:
    """
    Find language-specific build/manifest files in the repo.
    Returns {language: [file_paths]}.
    """
    g = get_client()
    repo = g.get_repo(repo_full_name)
    detected: dict[str, list[str]] = {}

    checks = {
        "java":       ["pom.xml", "build.gradle", "build.gradle.kts"],
        "javascript": ["package.json", "tsconfig.json"],
        "python":     ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"],
        "go":         ["go.mod"],
        "ruby":       ["Gemfile"],
        "rust":       ["Cargo.toml"],
        "csharp":     ["*.csproj", "packages.config"],
        "c":          ["CMakeLists.txt", "Makefile", "configure.ac"],
    }

    for lang, files in checks.items():
        for fname in files:
            try:
                results = list(g.search_code(f'repo:{repo_full_name} filename:{fname}'))
                if results:
                    detected.setdefault(lang, []).extend([r.path for r in results])
            except GithubException:
                pass

    return detected


# ---------------------------------------------------------------------------
# Layer 4: Framework detection
# ---------------------------------------------------------------------------

def detect_frameworks(repo_full_name: str, language: str) -> list[dict]:
    """
    Search for known framework signatures in manifest/config files.
    Returns list of {framework, evidence_file, snippet}.
    """
    g = get_client()
    frameworks_map = {
        "java":       ["spring-boot", "quarkus", "micronaut", "struts", "jersey", "dropwizard"],
        "javascript": ["express", "nestjs", "next.js", "fastify", "koa", "hapi"],
        "python":     ["django", "flask", "fastapi", "tornado", "starlette", "pyramid"],
        "ruby":       ["rails", "sinatra", "hanami"],
        "go":         ["gin", "echo", "fiber", "chi", "gorilla"],
        "rust":       ["actix", "axum", "rocket", "warp"],
    }

    candidates = frameworks_map.get(language, [])
    found = []

    for fw in candidates:
        try:
            results = list(g.search_code(f'repo:{repo_full_name} "{fw}"'))
            if results:
                found.append({
                    "framework": fw,
                    "evidence_file": results[0].path,
                    "match_count": len(results),
                })
        except GithubException:
            pass

    return found


# ---------------------------------------------------------------------------
# Layer 5: Library version scanning
# ---------------------------------------------------------------------------

def get_manifest_content(repo_full_name: str, ecosystem: str) -> list[dict]:
    """
    Fetch manifest file content for a given ecosystem.
    Returns list of {path, content}.
    """
    g = get_client()
    manifests = MANIFEST_FILES.get(ecosystem, [])
    results = []

    for manifest in manifests:
        fname = manifest.replace("*.", "")  # strip glob prefix for search
        try:
            hits = list(g.search_code(f'repo:{repo_full_name} filename:{fname}'))
            for hit in hits:
                content = get_file_content(repo_full_name, hit.path)
                if content:
                    results.append({"path": hit.path, "content": content})
        except GithubException:
            pass

    return results


def parse_library_versions(manifest_path: str, content: str) -> list[dict]:
    """
    Parse library names and versions from common manifest files.
    Returns list of {name, version, ecosystem}.
    """
    path = manifest_path.lower()
    libs = []

    if "pom.xml" in path:
        # Maven: <artifactId>...</artifactId> + <version>...</version>
        deps = re.findall(
            r"<dependency>.*?<artifactId>(.*?)</artifactId>.*?(?:<version>(.*?)</version>)?.*?</dependency>",
            content, re.DOTALL
        )
        for artifact, version in deps:
            libs.append({"name": artifact.strip(), "version": version.strip() or "unknown", "ecosystem": "maven"})

    elif "package.json" in path and "lock" not in path:
        # npm: "name": "version"
        deps = re.findall(r'"([^"]+)":\s*"([^"]+)"', content)
        for name, version in deps:
            if not name.startswith("@types") and name not in ("name", "version", "description"):
                libs.append({"name": name, "version": version, "ecosystem": "npm"})

    elif "requirements.txt" in path:
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                parts = re.split(r"[=<>!~]", line, 1)
                name = parts[0].strip()
                version = line[len(name):].strip() or "unspecified"
                libs.append({"name": name, "version": version, "ecosystem": "pypi"})

    elif "go.mod" in path:
        for line in content.splitlines():
            m = re.match(r"\s*([\w./\-]+)\s+(v[\d.]+[-\w]*)", line)
            if m:
                libs.append({"name": m.group(1), "version": m.group(2), "ecosystem": "go"})

    elif "gemfile" in path and "lock" not in path:
        for line in content.splitlines():
            m = re.match(r"\s*gem ['\"]([^'\"]+)['\"](?:,\s*['\"]([^'\"]+)['\"])?", line)
            if m:
                libs.append({"name": m.group(1), "version": m.group(2) or "unspecified", "ecosystem": "gem"})

    elif "cargo.toml" in path:
        for line in content.splitlines():
            m = re.match(r'([a-z_\-]+)\s*=\s*["\']([^"\']+)["\']', line)
            if m:
                libs.append({"name": m.group(1), "version": m.group(2), "ecosystem": "cargo"})

    return libs


# ---------------------------------------------------------------------------
# Layer 6: Code pattern search
# ---------------------------------------------------------------------------

def search_code_in_org(org_name: str, pattern: str, language: Optional[str] = None) -> list[dict]:
    """Search GitHub code for a pattern within an org."""
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


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def get_file_content(repo_full_name: str, file_path: str, ref: str = "HEAD") -> Optional[str]:
    """Fetch raw content of a file from a repo."""
    g = get_client()
    try:
        repo = g.get_repo(repo_full_name)
        content = repo.get_contents(file_path, ref=ref)
        if isinstance(content, list):
            return None
        return base64.b64decode(content.content).decode("utf-8", errors="replace")
    except GithubException:
        return None


def create_branch(repo_full_name: str, branch_name: str, from_branch: str = "main") -> bool:
    g = get_client()
    try:
        repo = g.get_repo(repo_full_name)
        source = repo.get_branch(from_branch)
        repo.create_git_ref(f"refs/heads/{branch_name}", source.commit.sha)
        return True
    except GithubException as e:
        print(f"[github_tools] create_branch error: {e}")
        return False


def update_file(repo_full_name: str, file_path: str, new_content: str,
                branch: str, commit_message: str) -> bool:
    g = get_client()
    try:
        repo = g.get_repo(repo_full_name)
        try:
            existing = repo.get_contents(file_path, ref=branch)
            repo.update_file(file_path, commit_message, new_content, existing.sha, branch=branch)
        except GithubException:
            repo.create_file(file_path, commit_message, new_content, branch=branch)
        return True
    except GithubException as e:
        print(f"[github_tools] update_file error: {e}")
        return False


def create_pull_request(repo_full_name: str, head_branch: str, base_branch: str,
                        title: str, body: str) -> Optional[str]:
    g = get_client()
    try:
        repo = g.get_repo(repo_full_name)
        pr = repo.create_pull(title=title, body=body, head=head_branch, base=base_branch)
        return pr.html_url
    except GithubException as e:
        print(f"[github_tools] create_pull_request error: {e}")
        return None


def get_pr_files(repo_full_name: str, pr_number: int) -> list[dict]:
    g = get_client()
    try:
        repo = g.get_repo(repo_full_name)
        pr = repo.get_pull(pr_number)
        return [
            {"filename": f.filename, "status": f.status,
             "additions": f.additions, "deletions": f.deletions, "patch": f.patch}
            for f in pr.get_files()
        ]
    except GithubException:
        return []


def get_pr_status(repo_full_name: str, pr_number: int) -> dict:
    g = get_client()
    try:
        repo = g.get_repo(repo_full_name)
        pr = repo.get_pull(pr_number)
        commit = repo.get_commit(pr.head.sha)
        checks = [{"name": s.context, "state": s.state} for s in commit.get_statuses()]
        return {"state": pr.state, "merged": pr.merged, "mergeable": pr.mergeable, "checks": checks}
    except GithubException:
        return {}

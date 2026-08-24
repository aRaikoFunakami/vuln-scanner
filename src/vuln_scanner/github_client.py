"""GitHub API client using gh CLI."""

import json
import shutil
import subprocess
import sys
import time
import base64

# Dependency file patterns — dynamically collected from registered threats.
from vuln_scanner.threats import get_all_file_patterns_regex
DEPENDENCY_FILE_PATTERNS = get_all_file_patterns_regex()


# Allowlist of permitted gh subcommands and API path prefixes.
# Only read-only operations are allowed.
_ALLOWED_GH_SUBCOMMANDS = {"api", "auth"}
_ALLOWED_API_PATH_PREFIXES = (
    "/user",
    "/users/",
    "/orgs/",
    "/repos/",
    "/search/",
)
_FORBIDDEN_API_FLAGS = {"-X", "--method"}


def _validate_gh_args(args):
    """Ensure gh arguments are read-only operations only.

    Raises ValueError if a disallowed subcommand, API path, or HTTP method
    override is detected.
    """
    if not args:
        raise ValueError("Empty gh arguments")

    subcommand = args[0]
    if subcommand not in _ALLOWED_GH_SUBCOMMANDS:
        raise ValueError(f"Disallowed gh subcommand: {subcommand}")

    # Check for forbidden flags that could change HTTP method
    for arg in args:
        if arg in _FORBIDDEN_API_FLAGS:
            raise ValueError(
                f"Disallowed flag '{arg}': only GET (read-only) requests are permitted"
            )

    # For 'api' subcommand, validate the endpoint path
    if subcommand == "api":
        # Find the API path (first positional arg after 'api')
        api_path = None
        skip_next = False
        for arg in args[1:]:
            if skip_next:
                skip_next = False
                continue
            if arg in ("--jq", "-q", "--template", "-t", "--paginate", "-p",
                       "--hostname", "--cache", "-H", "--header", "-f", "--field",
                       "-F", "--raw-field"):
                skip_next = True
                continue
            if arg.startswith("-"):
                continue
            api_path = arg
            break

        if api_path and not any(
            api_path.startswith(prefix) for prefix in _ALLOWED_API_PATH_PREFIXES
        ):
            raise ValueError(
                f"Disallowed API path: {api_path}. "
                f"Allowed prefixes: {_ALLOWED_API_PATH_PREFIXES}"
            )


def _run_gh(args, ignore_errors=False):
    """Run a gh CLI command and return parsed JSON output.

    Only read-only (GET) operations are permitted.
    Handles paginated output that may contain multiple JSON arrays/objects.
    """
    _validate_gh_args(args)
    cmd = ["gh"] + args
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        if ignore_errors:
            return None
        # Handle rate limiting
        if "rate limit" in result.stderr.lower() or "403" in result.stderr:
            print("  Rate limited, waiting 60s...", file=sys.stderr)
            time.sleep(60)
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return None
        else:
            return None
    if not result.stdout.strip():
        return None

    # Handle paginated output: gh --paginate may concatenate multiple JSON arrays
    output = result.stdout.strip()
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        # Try to parse as multiple JSON objects/arrays concatenated
        decoder = json.JSONDecoder()
        results = []
        idx = 0
        while idx < len(output):
            # Skip whitespace
            while idx < len(output) and output[idx] in ' \t\n\r':
                idx += 1
            if idx >= len(output):
                break
            obj, end_idx = decoder.raw_decode(output, idx)
            if isinstance(obj, list):
                results.extend(obj)
            else:
                results.append(obj)
            idx = end_idx
        return results if results else None


def check_auth():
    """Verify gh CLI is installed and authenticated. Returns username or exits."""
    if not shutil.which("gh"):
        print("Error: GitHub CLI (gh) がインストールされていません。", file=sys.stderr)
        print("", file=sys.stderr)
        print("インストール方法:", file=sys.stderr)
        print("  Mac:   brew install gh", file=sys.stderr)
        print("  Linux: https://github.com/cli/cli/blob/trunk/docs/install_linux.md", file=sys.stderr)
        print("", file=sys.stderr)
        print("インストール後に 'gh auth login' で認証してください。", file=sys.stderr)
        sys.exit(2)
    result = subprocess.run(
        ["gh", "auth", "status"], capture_output=True, text=True
    )
    if result.returncode != 0:
        print("Error: gh CLI が認証されていません。", file=sys.stderr)
        print("'gh auth login' を実行してください。", file=sys.stderr)
        sys.exit(2)
    # --jq returns raw string, not JSON
    result = subprocess.run(
        ["gh", "api", "/user", "--jq", ".login"],
        capture_output=True, text=True,
    )
    return result.stdout.strip()


_REPO_JQ = '[.[] | {full_name: .full_name, default_branch: .default_branch, fork: .fork, archived: .archived}]'


def _filter_repos(repos, repos_filter):
    """Filter repos by full_name or short name."""
    if not repos_filter:
        return repos
    filter_set = {r.strip() for r in repos_filter}
    return [
        r for r in repos
        if r["full_name"] in filter_set
        or r["full_name"].split("/")[-1] in filter_set
    ]


# Each getter returns None when the listing could not be fetched (rate
# limit / auth / 404), so the caller can tell that apart from a genuinely
# empty result and not report a failed scan as "clean" (issue #27). A
# real empty listing comes back as [] because the --jq always emits an
# array on success.


def get_user_repos(username=None, repos_filter=None):
    """Get all repositories for the authenticated user, or None on failure."""
    data = _run_gh([
        "api", "/user/repos",
        "--paginate",
        "--jq", _REPO_JQ,
    ])
    return None if data is None else _filter_repos(data, repos_filter)


def get_specific_user_repos(username, repos_filter=None):
    """Get public repositories for a specific GitHub user, or None on failure."""
    data = _run_gh([
        "api", f"/users/{username}/repos",
        "--paginate",
        "--jq", _REPO_JQ,
    ])
    return None if data is None else _filter_repos(data, repos_filter)


def get_org_repos(org, repos_filter=None):
    """Get repositories for a GitHub organization, or None on failure."""
    data = _run_gh([
        "api", f"/orgs/{org}/repos",
        "--paginate",
        "--jq", _REPO_JQ,
    ])
    return None if data is None else _filter_repos(data, repos_filter)


def get_dependency_files(owner_repo, default_branch):
    """Get dependency-file entries from a repository using the Tree API.

    Returns:
        ``None`` if the file list could not be fetched (rate limit, API
        error, empty repo) -- so the caller can tell "could not analyze"
        from "no dependency files" (issue #27) -- otherwise a list of
        ``{"path", "sha", "size"}`` dicts (possibly empty).
    """
    data = _run_gh([
        "api",
        f"/repos/{owner_repo}/git/trees/{default_branch}?recursive=1",
    ], ignore_errors=True)

    if not isinstance(data, dict) or "tree" not in data:
        return None

    matched = []
    for item in data["tree"]:
        if item.get("type") != "blob":
            continue
        path = item.get("path", "")
        for pattern in DEPENDENCY_FILE_PATTERNS:
            if pattern.search(path):
                matched.append({
                    "path": path,
                    "sha": item.get("sha"),
                    "size": item.get("size", 0),
                })
                break

    return matched


def get_file_content(owner_repo, file_path, sha=None):
    """Get decoded file content from a repository.

    The Contents API returns ``encoding: "none"`` with empty content for
    blobs larger than 1 MB -- the file most likely to carry a real
    transitive hit (a big lockfile). Fall back to the Git blobs API
    (up to 100 MB) using the blob *sha* so those are not silently missed
    (issue #27).

    Returns:
        File content as string, or None on failure.
    """
    def _decode(payload):
        if payload and payload.get("encoding") == "base64" and payload.get("content"):
            try:
                return base64.b64decode(payload["content"]).decode(
                    "utf-8", errors="replace"
                )
            except Exception:
                return None
        return None

    data = _run_gh([
        "api", f"/repos/{owner_repo}/contents/{file_path}",
    ], ignore_errors=True)
    content = _decode(data)
    if content is not None:
        return content

    # Large file (Contents API gave encoding "none"): fetch the raw blob.
    if sha:
        blob = _run_gh([
            "api", f"/repos/{owner_repo}/git/blobs/{sha}",
        ], ignore_errors=True)
        return _decode(blob)

    return None

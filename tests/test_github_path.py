"""GitHub-scan-path regression tests (run: python3 tests/test_github_path.py).

The GitHub path used to treat every fetch/parse failure as "clean, exit 0"
(issue #27) -- the C01/#11 "not analyzed must not look like clean" contract
never reached it. These tests mock github_client._run_gh so they need no gh
CLI or network, and assert:
  - a >1MB lockfile (Contents API returns encoding "none") is fetched via the
    Git blobs API and its transitive vuln is still detected;
  - an unfetchable file list / file content becomes a NOT_ANALYZED finding,
    not a silent clean;
  - a failed repo listing is distinguishable from a genuinely empty one.
"""

import base64
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import vuln_scanner.github_client as gh  # noqa: E402
from vuln_scanner.scanner import scan_github_repo  # noqa: E402

_LOGGER = logging.getLogger("test_github_path")
_LOGGER.addHandler(logging.NullHandler())


def _b64(s):
    return base64.b64encode(s.encode()).decode()


def test_large_lockfile_uses_blob_api():
    """A >1MB lockfile (Contents API gives encoding 'none') must be fetched
    via the blobs API so its transitive vulnerable pin is still found."""
    big_lock = _b64('{"packages": {"node_modules/axios": {"version": "1.14.1"}}}')

    def fake(args, ignore_errors=False):
        path = args[1]
        if "git/trees" in path:
            return {"tree": [
                {"type": "blob", "path": "package-lock.json",
                 "sha": "sha1", "size": 2_000_000},
            ]}
        if "contents" in path:
            return {"encoding": "none", "content": ""}   # >1MB
        if "blobs" in path:
            return {"encoding": "base64", "content": big_lock}
        return None

    orig = gh._run_gh
    gh._run_gh = fake
    try:
        findings, _n = scan_github_repo("o/r", "main", _LOGGER)
    finally:
        gh._run_gh = orig
    axios = [f for f in findings if f["package"] == "axios"]
    assert axios and axios[0]["verdict"] == "VULNERABLE", findings


def test_unfetchable_tree_is_not_analyzed():
    """A repo whose file list can't be fetched must produce a NOT_ANALYZED
    finding, not read as a clean repo."""
    orig = gh._run_gh
    gh._run_gh = lambda args, ignore_errors=False: None
    try:
        findings, _n = scan_github_repo("o/r", "main", _LOGGER)
    finally:
        gh._run_gh = orig
    assert findings and all(f["verdict"] == "NOT_ANALYZED" for f in findings), findings


def test_unfetchable_content_is_not_analyzed():
    """A dep file listed but whose content can't be fetched (contents AND
    blob both fail) must be NOT_ANALYZED, not silently skipped."""
    def fake(args, ignore_errors=False):
        if "git/trees" in args[1]:
            return {"tree": [
                {"type": "blob", "path": "package.json", "sha": "s", "size": 40},
            ]}
        return None  # contents + blob both fail

    orig = gh._run_gh
    gh._run_gh = fake
    try:
        findings, _n = scan_github_repo("o/r", "main", _LOGGER)
    finally:
        gh._run_gh = orig
    assert any(
        f["file_path"] == "package.json" and f["verdict"] == "NOT_ANALYZED"
        for f in findings
    ), findings


def test_repo_listing_failure_distinct_from_empty():
    """A failed repo listing returns None (caller exits 2); a genuinely
    empty listing returns []."""
    orig = gh._run_gh
    try:
        gh._run_gh = lambda args, ignore_errors=False: None
        assert gh.get_org_repos("org") is None
        gh._run_gh = lambda args, ignore_errors=False: []
        assert gh.get_org_repos("org") == []
    finally:
        gh._run_gh = orig


def test_normal_repo_still_detects_and_stays_clean():
    """A normal small repo: vulnerable pin detected, and a clean repo yields
    no NOT_ANALYZED noise."""
    vuln = _b64('{"dependencies": {"axios": "1.14.1"}}')
    clean = _b64('{"dependencies": {"axios": "1.0.0"}}')

    def make_fake(content_b64):
        def fake(args, ignore_errors=False):
            if "git/trees" in args[1]:
                return {"tree": [
                    {"type": "blob", "path": "package.json", "sha": "s", "size": 40},
                ]}
            if "contents" in args[1]:
                return {"encoding": "base64", "content": content_b64}
            return None
        return fake

    orig = gh._run_gh
    try:
        gh._run_gh = make_fake(vuln)
        findings, _n = scan_github_repo("o/r", "main", _LOGGER)
        assert any(f["package"] == "axios" and f["verdict"] == "VULNERABLE"
                   for f in findings), findings

        gh._run_gh = make_fake(clean)
        findings, _n = scan_github_repo("o/r", "main", _LOGGER)
        assert not any(f["verdict"] == "NOT_ANALYZED" for f in findings), findings
        assert any(f["package"] == "axios" and f["verdict"] == "SAFE"
                   for f in findings), findings
    finally:
        gh._run_gh = orig


def main():
    test_large_lockfile_uses_blob_api()
    test_unfetchable_tree_is_not_analyzed()
    test_unfetchable_content_is_not_analyzed()
    test_repo_listing_failure_distinct_from_empty()
    test_normal_repo_still_detects_and_stays_clean()
    print("OK")


if __name__ == "__main__":
    main()

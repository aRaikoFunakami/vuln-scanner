"""CLI contract tests (run directly: python3 tests/test_cli.py).

CLAUDE.md レビュー観点5: E2E scans over real fixture projects for both
ecosystems, and exit codes usable as a CI gate (VULNERABLE -> non-zero).

Exit codes: 0 = clean, 1 = VULNERABLE, 2 = operational error,
3 = a dependency file could not be analyzed (issue #11).
"""

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(HERE, "fixtures")

# Structural E2E fixtures (lockfile formats, npm hoist/pnpm-store/nested
# node_modules layouts, corrupted JSON) use DUMMY package identifiers --
# see fixtures/dummy_threats.json -- so this repo never carries genuinely
# vulnerable-looking package/version strings on disk. A scan of a
# directory that merely CONTAINS this checkout (e.g. `--local ~/GitHub`)
# is therefore inert against them by construction, with no exclusion
# mechanism needed: they simply don't match the real threats.json.
DUMMY_THREATS_JSON = os.path.join(FIXTURES, "dummy_threats.json")


def run_scan(project_dir, threats_json=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in [os.path.join(ROOT, "src"), env.get("PYTHONPATH")] if p
    )
    if threats_json:
        env["VULN_SCANNER_THREATS_JSON"] = threats_json
    with tempfile.TemporaryDirectory() as out:
        return subprocess.run(
            [
                sys.executable, "-m", "vuln_scanner.scanner",
                "--local", project_dir, "--output-dir", out,
            ],
            capture_output=True, text=True, env=env, timeout=120,
        )


# (fixture, expected exit code, string that must appear in stdout)
# - e2e-npm: package.json pins only a safe range; exit 1 can only come
#   from the lockfile path (parse + enrich), so a lock-parser regression
#   turns this red instead of hiding behind the package.json finding.
# - e2e-clean: the stdout marker proves files were actually scanned --
#   "scanned nothing" must not pass as "scanned clean". Host malware-
#   artifact paths no longer affect this exit code (issue #29); a pip
#   freeze of the running interpreter that has a vulnerable target
#   installed still would, which is the scanner working.
CASES = [
    ("e2e-npm", 1, "vsfixture-cache"),
    ("e2e-yarn", 1, "vsfixture-cache"),
    # package.json declares the vulnerable range with no lockfile pin --
    # detected only via the node_modules disk scan (issue #10 follow-up:
    # this exact combination used to crash enrich_findings)
    ("e2e-npm-nodemod-only", 1, "vsfixture-cache"),
    # Python package names are PEP 503-normalized (hyphen -> underscore)
    # in output, so match on the stable substring.
    ("e2e-python", 1, "llmclient"),
    ("e2e-clean", 0, "スキャン対象ファイル数: 2"),
    # corrupted package.json: no VULNERABLE finding possible, so exit 3
    # ("not analyzed") must fire -- not the exit 0 "clean" a silently
    # empty parse result would otherwise produce (issue #11)
    ("disk-corrupted-json", 3, "NOT_ANALYZED"),
]


def test_exit_codes():
    for name, expected, marker in CASES:
        proc = run_scan(os.path.join(FIXTURES, name), threats_json=DUMMY_THREATS_JSON)
        assert proc.returncode == expected, (
            name, proc.returncode, proc.stdout[-2000:], proc.stderr[-500:],
        )
        assert marker in proc.stdout, (name, marker, proc.stdout[-2000:])


def test_persisted_fixtures_inert_against_real_threats_db():
    """Regression guard: this repo's own tests/fixtures/ (used by
    test_exit_codes above) must be INERT against the REAL production
    threats.json -- their package identifiers are dummies the real DB
    has never heard of. A real `--local` scan of a directory that
    happens to contain this checkout (e.g. `--local ~/GitHub`) must
    therefore never flag them as live findings, with no exclusion/
    allowlist mechanism required."""
    for name, _expected, _marker in CASES:
        if name in ("e2e-clean", "disk-corrupted-json"):
            continue  # nothing vulnerable in these regardless of DB
        proc = run_scan(os.path.join(FIXTURES, name))  # no threats_json override
        assert proc.returncode == 0, (name, proc.returncode, proc.stdout[-2000:])


def test_real_threats_db_detects_via_full_cli():
    """Sanity check that the REAL production threats.json still works
    end to end through the full CLI -- using an EPHEMERAL project (never
    committed to the repo) rather than a persisted fixture, so this
    repo never carries a real vulnerable-looking package/version on
    disk (see DUMMY_THREATS_JSON above)."""
    with tempfile.TemporaryDirectory() as proj:
        with open(os.path.join(proj, "requirements.txt"), "w") as f:
            f.write("litellm==1.82.7\n")
        proc = run_scan(proj)  # no threats_json override -- real DB
    assert proc.returncode == 1, (proc.returncode, proc.stdout[-2000:])
    assert "litellm" in proc.stdout, proc.stdout[-2000:]


def test_host_artifact_does_not_fail_repo_gate():
    """Regression guard (#29): a host-level malware artifact present on the
    machine must NOT make a clean repo's scan exit non-zero. Runs the CLI
    with HOME pointed at a temp dir containing the keyv Darwin artifact so
    the probe fires without touching the real host."""
    import platform

    if platform.system() != "Darwin":
        return  # artifact path set is platform-specific; keep the test hermetic

    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in [os.path.join(ROOT, "src"), env.get("PYTHONPATH")] if p
    )
    with tempfile.TemporaryDirectory() as home, \
            tempfile.TemporaryDirectory() as proj, \
            tempfile.TemporaryDirectory() as out:
        agents = os.path.join(home, "Library", "LaunchAgents")
        os.makedirs(agents)
        open(os.path.join(agents, "com.user.gh-token-monitor.plist"), "w").close()
        with open(os.path.join(proj, "package.json"), "w") as f:
            f.write('{"name": "clean", "version": "1.0.0"}')
        env["HOME"] = home
        proc = subprocess.run(
            [sys.executable, "-m", "vuln_scanner.scanner",
             "--local", proj, "--output-dir", out],
            capture_output=True, text=True, env=env, timeout=120,
        )
    # clean repo, host artifact present -> still exit 0 (artifact excluded
    # from the gate) but surfaced in the report
    assert proc.returncode == 0, (proc.returncode, proc.stdout[-2000:])
    assert "malware" in proc.stdout.lower() or "マルウェア" in proc.stdout


def main():
    test_exit_codes()
    test_persisted_fixtures_inert_against_real_threats_db()
    test_real_threats_db_detects_via_full_cli()
    test_host_artifact_does_not_fail_repo_gate()
    print("OK")


if __name__ == "__main__":
    main()

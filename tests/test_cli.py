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


def run_scan(project_dir):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in [os.path.join(ROOT, "src"), env.get("PYTHONPATH")] if p
    )
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
#   "scanned nothing" must not pass as "scanned clean".
#   NOTE: this case scans the HOST too (pip freeze of the running
#   interpreter, malware-artifact paths); a hit there makes it exit 1 on
#   a genuinely compromised machine, which is the scanner working.
CASES = [
    ("e2e-npm", 1, "keyv"),
    ("e2e-yarn", 1, "keyv"),
    # package.json declares the vulnerable range with no lockfile pin --
    # detected only via the node_modules disk scan (issue #10 follow-up:
    # this exact combination used to crash enrich_findings)
    ("e2e-npm-nodemod-only", 1, "keyv"),
    ("e2e-python", 1, "litellm"),
    ("e2e-clean", 0, "スキャン対象ファイル数: 2"),
    # corrupted package.json: no VULNERABLE finding possible, so exit 3
    # ("not analyzed") must fire -- not the exit 0 "clean" a silently
    # empty parse result would otherwise produce (issue #11)
    ("disk-corrupted-json", 3, "NOT_ANALYZED"),
]


def test_exit_codes():
    for name, expected, marker in CASES:
        proc = run_scan(os.path.join(FIXTURES, name))
        assert proc.returncode == expected, (
            name, proc.returncode, proc.stdout[-2000:], proc.stderr[-500:],
        )
        assert marker in proc.stdout, (name, marker, proc.stdout[-2000:])


def main():
    test_exit_codes()
    print("OK")


if __name__ == "__main__":
    main()

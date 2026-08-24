"""CLI contract tests (run directly: python3 tests/test_cli.py).

CLAUDE.md レビュー観点5: E2E scans over real fixture projects for both
ecosystems, and exit codes usable as a CI gate (VULNERABLE -> non-zero).
"""

import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def run_scan(project_dir):
    with tempfile.TemporaryDirectory() as out:
        env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"))
        return subprocess.run(
            [
                sys.executable, "-m", "vuln_scanner.scanner",
                "--local", project_dir, "--output-dir", out,
            ],
            capture_output=True, text=True, env=env, timeout=120,
        )


def main():
    # npm ecosystem: vulnerable fixture project -> exit 1 (CI gate)
    proc = run_scan(os.path.join(FIXTURES, "e2e-npm"))
    assert proc.returncode == 1, (
        proc.returncode, proc.stdout[-2000:], proc.stderr[-500:],
    )

    # python ecosystem: vulnerable fixture project -> exit 1
    proc = run_scan(os.path.join(FIXTURES, "e2e-python"))
    assert proc.returncode == 1, (
        proc.returncode, proc.stdout[-2000:], proc.stderr[-500:],
    )

    # clean fixture project -> exit 0
    proc = run_scan(os.path.join(FIXTURES, "e2e-clean"))
    assert proc.returncode == 0, (
        proc.returncode, proc.stdout[-2000:], proc.stderr[-500:],
    )

    print("OK")


if __name__ == "__main__":
    main()

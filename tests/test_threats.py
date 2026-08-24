"""Self-check for the threat registry (run directly: python3 tests/test_threats.py).

Guards against the `all_packages` regression where a threat with many
`direct_packages` entries (e.g. a mass npm worm) only exposed one of them
for parsing/judgment.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from vuln_scanner.threats import get_all_threats, judge  # noqa: E402
from vuln_scanner.threats.ecosystems.npm import (  # noqa: E402
    parse_package_lock_json,
    parse_pnpm_lock,
)


def test_enrich_does_not_flip_verdicts():
    """Regression guard (#5): an unrelated threat's enrich_findings must
    judge across all registered threats -- its own judge returns SAFE for
    out-of-scope packages, which used to flip existing VULNERABLE verdicts
    when a new npm threat was appended to threats.json."""
    import json
    import tempfile

    from vuln_scanner.threats.data_driven import DataDrivenThreat
    from vuln_scanner.threats.ecosystems import npm as npm_eco

    dummy = DataDrivenThreat(
        {
            "name": "unrelated-example",
            "ecosystem": "npm",
            "direct_packages": {"lodash": ["4.99.99"]},
        },
        npm_eco,
    )

    with tempfile.TemporaryDirectory() as root:
        lock_path = os.path.join(root, "package-lock.json")
        with open(lock_path, "w") as f:
            json.dump(
                {"packages": {"node_modules/keyv": {"version": "6.0.0"}}}, f
            )
        findings = [{
            "repo": root,
            "file_path": "package.json",
            "package": "keyv",
            "version": None,
            "verdict": "WARNING",
            "note": "",
            "source": "dependency_file",
        }]
        dummy.enrich_findings(findings, [], [lock_path], root)

    assert findings[0]["version"] == "6.0.0", findings[0]
    assert findings[0]["verdict"] == "VULNERABLE", findings[0]


def main():
    threats = {t.name: t for t in get_all_threats()}

    keyv = threats["keyv"]
    assert len(keyv.all_packages) == 394, len(keyv.all_packages)
    assert judge("keyv", "6.0.0")[0] == "VULNERABLE"
    assert judge("keyv", "5.0.0")[0] == "SAFE"
    assert judge("@crawlee/core", "3.17.1-beta.80")[0] == "VULNERABLE"
    assert judge("cache-manager", "8.0.0")[0] == "SAFE"

    # Regression guard: with 394 packages sharing one threat, a version
    # malicious for package A must not be flagged VULNERABLE for unrelated
    # package B just because the version string happens to collide.
    assert judge("@adminide-stack/clock-tik-browser", "1.81.0")[0] == "SAFE"
    assert judge("@adminide-stack/clock-tik-browser", "12.0.24")[0] == "VULNERABLE"
    assert judge("@7n/rules", "1.81.0")[0] == "VULNERABLE"

    # Regression guard: scoped package names must survive lockfile parsing
    # (package-lock.json v2/v3 and pnpm-lock.yaml both strip everything
    # before the last "/" naively if not handled).
    targets = {"@arv-bedrock/auth", "keyv"}
    lock_json = (
        '{"packages": {'
        '"node_modules/@arv-bedrock/auth": {"version": "1.1.7"}, '
        '"node_modules/keyv": {"version": "6.0.0"}'
        "}}"
    )
    assert set(parse_package_lock_json(lock_json, targets)) == {
        ("@arv-bedrock/auth", "1.1.7"),
        ("keyv", "6.0.0"),
    }
    pnpm_content = "/@arv-bedrock/auth@1.1.7:\n" "/keyv@6.0.0:\n"
    assert set(parse_pnpm_lock(pnpm_content, targets)) == {
        ("@arv-bedrock/auth", "1.1.7"),
        ("keyv", "6.0.0"),
    }

    # Regression guard: single direct_package threats still work.
    axios = threats["axios"]
    assert axios.all_packages == {"axios", "plain-crypto-js"}
    assert judge("axios", "1.14.1")[0] == "VULNERABLE"
    assert judge("plain-crypto-js", None)[0] == "VULNERABLE"

    test_enrich_does_not_flip_verdicts()

    print("OK")


if __name__ == "__main__":
    main()

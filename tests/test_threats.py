"""Self-check for the threat registry (run directly: python3 tests/test_threats.py).

Guards against the `all_packages` regression where a threat with many
`direct_packages` entries (e.g. a mass npm worm) only exposed one of them
for parsing/judgment.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from vuln_scanner.threats import (  # noqa: E402
    SAFE,
    VULNERABLE,
    WARNING,
    get_all_threats,
    judge,
)
from vuln_scanner.threats.ecosystems.npm import (  # noqa: E402
    parse_package_lock_json,
    parse_pnpm_lock,
)


# Real `npm install --package-lock-only` output (npm 11, lockfileVersion 3).
# The malicious keyv@6.0.0 is unpublished from the registry, so the lock was
# generated with benign versions and only the version strings / the dummy
# package name were substituted afterwards (CLAUDE.md レビュー観点1).
FIXTURE_LOCK = os.path.join(
    os.path.dirname(__file__), "fixtures", "package-lock.json"
)


def _make_finding(root, package):
    return {
        "repo": root,
        "file_path": "package.json",
        "package": package,
        "version": None,
        "verdict": WARNING,
        "note": "",
        "source": "dependency_file",
    }


def test_enrich_does_not_flip_verdicts():
    """Regression guard (#5): appending a threat must not flip verdicts.

    Replays the local_scanner enrich phase with every registered threat
    plus an unrelated dummy appended LAST (the threats.json-append
    scenario): the dummy's own judge returns SAFE for out-of-scope
    packages and used to overwrite the keyv VULNERABLE verdict.
    Also pins:
    - a not-yet-registered threat still judges its own packages
    - enrichment is idempotent (a second full pass changes nothing)
    """
    import copy
    import shutil
    import tempfile

    from vuln_scanner.threats.data_driven import DataDrivenThreat
    from vuln_scanner.threats.ecosystems import npm as npm_eco

    dummy = DataDrivenThreat(
        {
            "name": "unrelated-example",
            "ecosystem": "npm",
            "direct_packages": {"vuln-scanner-selftest-pkg": ["4.99.99"]},
        },
        npm_eco,
    )

    with tempfile.TemporaryDirectory() as root:
        lock_path = os.path.join(root, "package-lock.json")
        shutil.copy(FIXTURE_LOCK, lock_path)
        findings = [
            _make_finding(root, "keyv"),
            _make_finding(root, "vuln-scanner-selftest-pkg"),
        ]
        threat_order = list(get_all_threats()) + [dummy]
        for threat in threat_order:
            threat.enrich_findings(findings, [], [lock_path], root)
        snapshot = copy.deepcopy(findings)
        for threat in threat_order:
            threat.enrich_findings(findings, [], [lock_path], root)
        assert findings == snapshot, "enrich must be idempotent"

    keyv_f, selftest_f = findings
    assert keyv_f["version"] == "6.0.0", keyv_f
    assert keyv_f["verdict"] == VULNERABLE, keyv_f
    # The unregistered dummy must still judge its own package
    assert selftest_f["version"] == "4.99.99", selftest_f
    assert selftest_f["verdict"] == VULNERABLE, selftest_f


def test_judge_worst_verdict_wins():
    """judge() must consult ALL owning threats (worst verdict wins) and
    honor the ecosystem filter -- npm and PyPI names collide."""
    # ecosystem filter: keyv is an npm threat
    assert judge("keyv", "6.0.0", ecosystem="npm")[0] == VULNERABLE
    assert judge("keyv", "6.0.0", ecosystem="python")[0] == SAFE
    assert judge("keyv", "6.0.0")[0] == VULNERABLE


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
    test_judge_worst_verdict_wins()

    print("OK")


if __name__ == "__main__":
    main()

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
    parse_yarn_lock,
)


def _fixture(name):
    return os.path.join(os.path.dirname(__file__), "fixtures", name)


# Real `npm install --package-lock-only` output (npm 11, lockfileVersion 3).
# The malicious keyv@6.0.0 is unpublished from the registry, so the lock was
# generated with benign versions and only the version strings / the dummy
# package name were substituted afterwards (CLAUDE.md レビュー観点1).
FIXTURE_LOCK = _fixture("package-lock.json")


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


def test_enrich_most_severe_lock_version():
    """A lockfile pinning both a safe and a vulnerable version of the same
    package (direct + transitive) must enrich to the vulnerable one, not
    to whichever version appears first in the file."""
    import json
    import tempfile

    with tempfile.TemporaryDirectory() as root:
        lock_path = os.path.join(root, "package-lock.json")
        with open(FIXTURE_LOCK) as f:
            lock = json.load(f)
        # Inject a nested (transitive) SAFE keyv using the entry shape npm
        # emits; sorted keys put it before the vulnerable one, which the
        # old first-wins pick would have reported.
        lock["packages"]["node_modules/a-pkg/node_modules/keyv"] = dict(
            lock["packages"]["node_modules/keyv"], version="5.0.0"
        )
        lock["packages"] = dict(sorted(lock["packages"].items()))
        with open(lock_path, "w") as f:
            json.dump(lock, f)
        findings = [_make_finding(root, "keyv")]
        for threat in get_all_threats():
            threat.enrich_findings(findings, [], [lock_path], root)

    assert findings[0]["version"] == "6.0.0", findings[0]
    assert findings[0]["verdict"] == VULNERABLE, findings[0]


def test_semver_ranges_never_assert_safe():
    """CLAUDE.md レビュー観点4 (#9): a range specifier must never be
    judged SAFE when it can resolve to a vulnerable version, and parsers
    must not strip range operators."""
    from vuln_scanner.threats.ecosystems.npm import parse_package_json
    from vuln_scanner.threats.ecosystems.python import parse_requirements_txt

    # Parsers keep the raw specifier
    pkg_json = '{"dependencies": {"axios": "^1.14.0"}}'
    assert parse_package_json(pkg_json, {"axios"}) == [("axios", "^1.14.0")]
    assert parse_requirements_txt("litellm>=1.82.0\n", {"litellm"}) == [
        ("litellm", ">=1.82.0")
    ]
    assert parse_requirements_txt("litellm==1.82.7\n", {"litellm"}) == [
        ("litellm", "1.82.7")
    ]

    # Ranges that can reach a vulnerable version -> WARNING, never SAFE
    # (axios vulnerable: 1.14.1, 0.30.4; litellm vulnerable: 1.82.7/8)
    assert judge("axios", "^1.14.0")[0] == WARNING
    assert judge("axios", "~1.14.0")[0] == WARNING
    assert judge("axios", ">=1.0.0")[0] == WARNING
    assert judge("axios", "^0.30.0")[0] == WARNING
    assert judge("axios", "*")[0] == WARNING
    assert judge("litellm", ">=1.82.0")[0] == WARNING
    assert judge("litellm", "~=1.82.0")[0] == WARNING

    # Ranges that cannot reach any vulnerable version -> SAFE (range form)
    assert judge("keyv", "^4.0.0")[0] == SAFE  # keyv vulnerable: 6.0.0
    assert judge("axios", "^2.0.0")[0] == SAFE
    assert judge("axios", "<0.30.0")[0] == SAFE

    # Exact pins keep exact semantics (incl. prerelease and PEP508 ==)
    assert judge("axios", "1.14.0")[0] == SAFE
    assert judge("axios", "1.14.1")[0] == VULNERABLE
    assert judge("litellm", "==1.82.7")[0] == VULNERABLE

    # "v" prefix is an exact pin, not a range -- must not fall through to
    # is_exact_version's SAFE branch without normalizing against the
    # bare version stored in threats.json (regression: was falsely SAFE)
    assert judge("axios", "v1.14.1")[0] == VULNERABLE
    assert judge("axios", "v1.14.0")[0] == SAFE
    pre = parse_package_json(
        '{"dependencies": {"@crawlee/core": "3.17.1-beta.80"}}',
        {"@crawlee/core"},
    )
    assert pre == [("@crawlee/core", "3.17.1-beta.80")], pre
    assert judge("@crawlee/core", "3.17.1-beta.80")[0] == VULNERABLE


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
    # All three pnpm lockfile generations, from real `pnpm install
    # --lockfile-only` output (pnpm 7 / 8 / 11) with names/versions
    # substituted -- the malicious versions are unpublished so a lock for
    # them cannot be generated directly (issue #6).
    # List (not set) equality: each package must be reported exactly once
    # (v9 repeats every package under `snapshots:`), scoped quoting must
    # not leak into versions, and `(peer)` / `_peer` suffixes must be
    # stripped.
    lock_targets = {
        "@arv-bedrock/auth", "keyv", "react", "use-sync-external-store",
    }
    lock_expected = [
        ("@arv-bedrock/auth", "1.1.7"),
        ("keyv", "6.0.0"),
        ("react", "18.3.1"),
        ("use-sync-external-store", "1.2.2"),
    ]
    for gen in ("v5", "v6", "v9"):
        with open(_fixture(f"pnpm-lock-{gen}.yaml")) as f:
            parsed = parse_pnpm_lock(f.read(), lock_targets)
        assert parsed == lock_expected, (gen, parsed)

    # yarn classic (v1) and berry (v2+), from real `yarn install` output
    # (yarn 1.22 / yarn 4.6) with names/versions substituted (issue #8).
    # Berry writes `version: 1.1.7` (colon-separated, unquoted), which the
    # parser previously could not read at all -- not even as WARNING.
    for gen in ("classic", "berry"):
        with open(_fixture(f"yarn-{gen}.lock")) as f:
            yarn_content = f.read()
        parsed = parse_yarn_lock(yarn_content, lock_targets)
        assert parsed == lock_expected, (gen, parsed)

    # Berry workspace entries carry the placeholder version
    # "0.0.0-use.local"; emitting it would judge the package SAFE with a
    # fabricated version.  (yarn_content still holds the berry fixture,
    # whose workspace entry is named "fixture".)
    assert parse_yarn_lock(yarn_content, {"fixture"}) == []

    # Berry v2/v3 lists one package under both npm: and virtual: headers
    # with the same version -- must be reported once.  (Synthetic
    # snippet: yarn 4 no longer emits virtual: entries.)
    virtual_dup = (
        '"react-dom@npm:18.3.1":\n'
        "  version: 18.3.1\n"
        '"react-dom@virtual:9f2b8c#npm:18.3.1":\n'
        "  version: 18.3.1\n"
    )
    assert parse_yarn_lock(virtual_dup, {"react-dom"}) == [
        ("react-dom", "18.3.1")
    ]

    # Negative space: keys outside the `packages:` section must not be
    # reported -- `overrides:` names a version that is not necessarily
    # installed, `snapshots:` would double-count.  (Synthetic snippet:
    # a does-not-detect probe, not lockfile fixture data.)
    not_installed = (
        "overrides:\n"
        "  keyv@6.0.0: ^7.0.0\n"
        "snapshots:\n"
        "  keyv@6.0.0:\n"
    )
    assert parse_pnpm_lock(not_installed, {"keyv"}) == []

    # Dotted package names (threats.json lists e.g. hamus.js) must parse
    assert parse_pnpm_lock(
        "packages:\n  hamus.js@1.0.4:\n", {"hamus.js"}
    ) == [("hamus.js", "1.0.4")]

    # Regression guard: single direct_package threats still work.
    axios = threats["axios"]
    assert axios.all_packages == {"axios", "plain-crypto-js"}
    assert judge("axios", "1.14.1")[0] == "VULNERABLE"
    assert judge("plain-crypto-js", None)[0] == "VULNERABLE"

    test_enrich_does_not_flip_verdicts()
    test_enrich_most_severe_lock_version()
    test_semver_ranges_never_assert_safe()
    test_judge_worst_verdict_wins()

    print("OK")


if __name__ == "__main__":
    main()

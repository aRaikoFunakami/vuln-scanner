"""Self-check for the threat registry (run directly: python3 tests/test_threats.py).

Guards against the `all_packages` regression where a threat with many
`direct_packages` entries (e.g. a mass npm worm) only exposed one of them
for parsing/judgment.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from vuln_scanner.threats import (  # noqa: E402
    NOT_ANALYZED,
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
    # Exact pins that are the SAME release as a vulnerable version but not
    # string-equal must canonicalize before the membership test, or they
    # slip to SAFE (#26): PEP 440 local metadata and leading zeros.
    assert judge("axios", "1.14.1+cpu")[0] == VULNERABLE
    assert judge("axios", "01.14.01")[0] == VULNERABLE
    assert judge("axios", "1.14.0+cpu")[0] == SAFE  # +meta must not over-match
    pre = parse_package_json(
        '{"dependencies": {"@crawlee/core": "3.17.1-beta.80"}}',
        {"@crawlee/core"},
    )
    assert pre == [("@crawlee/core", "3.17.1-beta.80")], pre
    assert judge("@crawlee/core", "3.17.1-beta.80")[0] == VULNERABLE


def test_python_parsers_preserve_range_operators():
    """Regression guard (#25): setup.py / setup.cfg / Dockerfile /
    pyproject PEP621-array must keep the range operator so judge() does
    not mistake `>=1.82.0` for the pinned version 1.82.0 and return SAFE
    (the #9 fix was only applied to requirements/pyproject-table/Pipfile).
    Also covers extras `[proxy]` and Dockerfile backslash continuations.
    """
    from vuln_scanner.threats.ecosystems.python import (
        parse_dockerfile,
        parse_pyproject_toml,
        parse_setup_cfg,
        parse_setup_py,
    )

    # litellm vulnerable: 1.82.7 / 1.82.8. `>=1.82.0` includes them.
    def verdict(specs):
        assert specs, "parser returned nothing"
        return judge("litellm", specs[0][1], ecosystem="python")[0]

    # setup.py: range → WARNING, exact pin → VULNERABLE, extras handled
    assert verdict(parse_setup_py(
        'install_requires=["litellm>=1.82.0"]', {"litellm"})) == WARNING
    assert verdict(parse_setup_py(
        'install_requires=["litellm[proxy]==1.82.7"]', {"litellm"})) == VULNERABLE
    # a dependency listed AFTER a bracketed extra must still be found
    assert verdict(parse_setup_py(
        'install_requires=["flask[async]>=2.0", "litellm==1.82.7"]',
        {"litellm"})) == VULNERABLE

    # setup.cfg indented-list form
    cfg = "install_requires =\n    requests>=2.0\n    litellm>=1.82.0\n"
    assert verdict(parse_setup_cfg(cfg, {"litellm"})) == WARNING

    # Dockerfile: inline range, exact pin, and backslash continuation
    assert verdict(parse_dockerfile(
        "RUN pip install litellm>=1.82.0", {"litellm"})) == WARNING
    assert verdict(parse_dockerfile(
        "RUN pip install --no-cache-dir \\\n    litellm==1.82.7 \\\n    requests",
        {"litellm"})) == VULNERABLE

    # pyproject PEP 621 array with extras / exact pin
    assert verdict(parse_pyproject_toml(
        'dependencies = ["litellm[proxy]==1.82.7"]', {"litellm"})) == VULNERABLE
    assert verdict(parse_pyproject_toml(
        'dependencies = ["litellm>=1.82.0"]', {"litellm"})) == WARNING

    # Regressions found reviewing #25:
    # PEP 440 local version (+cpu) is the same release as the vulnerable
    # 1.82.7 -- must not slip to SAFE (canonical_version fix).
    assert verdict(parse_setup_cfg(
        "install_requires =\n    litellm==1.82.7+cpu\n", {"litellm"})) == VULNERABLE
    assert verdict(parse_dockerfile(
        "RUN pip install litellm==1.82.7+cpu", {"litellm"})) == VULNERABLE
    # An exact vulnerable pin with an environment marker / inline comment
    # must stay VULNERABLE, not be demoted to WARNING by the swallowed tail.
    assert verdict(parse_setup_cfg(
        'install_requires =\n    litellm==1.82.7; python_version >= "3.8"\n',
        {"litellm"})) == VULNERABLE
    assert verdict(parse_setup_cfg(
        "install_requires =\n    litellm==1.82.7  # keep\n", {"litellm"})) == VULNERABLE
    # A package name appearing only in a comment / a later list must NOT
    # be reported as an install_requires dependency (greedy-capture fix).
    setup_comment = (
        "setup(\n"
        '    install_requires=["flask==2.0.0"],  # dropped litellm==1.82.7 (CVE)\n'
        '    classifiers=["X"],\n'
        ")\n"
    )
    assert parse_setup_py(setup_comment, {"litellm"}) == [], \
        parse_setup_py(setup_comment, {"litellm"})


def test_disk_scan_three_layouts():
    """CLAUDE.md レビュー観点2 (#10): disk scanning must find installed
    packages in all three node_modules layouts -- npm hoist, pnpm store
    (.pnpm/), and nested (non-hoisted) node_modules."""
    from vuln_scanner.local_scanner import scan_local

    cases = [
        ("disk-npm-hoist", "keyv", "6.0.0"),
        ("disk-pnpm-store", "keyv", "6.0.0"),
        ("disk-nested", "plain-crypto-js", "1.0.0"),
    ]
    for fixture_name, pkg, ver in cases:
        findings, _files, _installed = scan_local(_fixture(fixture_name), None)
        hits = [
            f for f in findings
            if f["package"] == pkg and f["verdict"] == VULNERABLE
        ]
        assert hits, (fixture_name, pkg, findings)
        assert any(f["version"] == ver for f in hits), (fixture_name, findings)


def test_disk_scan_no_false_positive_from_subtree():
    """Regression guard: matching must be bound to real node_modules
    boundaries. A decoy directory inside a package's own subtree
    (e.g. a shipped test fixture) that happens to share a target
    package's name must not be reported as an installed copy."""
    import json
    import tempfile

    from vuln_scanner.threats.ecosystems.npm import _walk_installed_versions

    with tempfile.TemporaryDirectory() as root:
        real = os.path.join(root, "node_modules", "keyv")
        os.makedirs(real)
        with open(os.path.join(real, "package.json"), "w") as f:
            json.dump({"name": "keyv", "version": "6.0.0"}, f)
        decoy = os.path.join(real, "test", "keyv")
        os.makedirs(decoy)
        with open(os.path.join(decoy, "package.json"), "w") as f:
            json.dump({"name": "keyv", "version": "9.9.9-decoy"}, f)
        result = _walk_installed_versions(root, {"keyv"})
    assert result == {"keyv": ["6.0.0"]}, result


def test_enrich_findings_handles_multi_version_installed():
    """Regression guard: enrich_findings' node_modules fallback must not
    crash when check_installed reports multiple on-disk versions of one
    package (issue #10 follow-up) -- a package.json dependency with no
    matching lockfile entry, resolved only from node_modules."""
    import json
    import tempfile

    with tempfile.TemporaryDirectory() as root:
        with open(os.path.join(root, "package.json"), "w") as f:
            json.dump(
                {"name": "x", "version": "1.0.0",
                 "dependencies": {"keyv": "^6.0.0"}}, f,
            )
        nm = os.path.join(root, "node_modules", "keyv")
        os.makedirs(nm)
        with open(os.path.join(nm, "package.json"), "w") as f:
            json.dump({"name": "keyv", "version": "6.0.0"}, f)
        from vuln_scanner.local_scanner import scan_local
        findings, _files, _installed = scan_local(root, None)

    keyv_hits = [f for f in findings if f["package"] == "keyv"]
    assert keyv_hits, findings
    assert any(f["verdict"] == VULNERABLE for f in keyv_hits), findings


def test_not_analyzed_never_looks_clean():
    """CLAUDE.md レビュー観点2 (#11): a dependency file that could not be
    parsed must not be indistinguishable from a genuinely clean scan."""
    from vuln_scanner.local_scanner import scan_local

    findings, _files, _installed = scan_local(_fixture("disk-corrupted-json"), None)
    not_analyzed = [f for f in findings if f["verdict"] == NOT_ANALYZED]
    assert not_analyzed, findings
    assert not_analyzed[0]["file_path"] == "package.json", not_analyzed

    # A genuinely clean, valid, dependency-free project must NOT be
    # flagged -- NOT_ANALYZED means "could not read", not "found nothing"
    clean_findings, _f, _i = scan_local(_fixture("e2e-clean"), None)
    assert not any(f["verdict"] == NOT_ANALYZED for f in clean_findings), clean_findings

    # Regression: the markdown 判定別サマリー table must show
    # NOT_ANALYZED, not silently omit it (a hardcoded 4-verdict list
    # used to drop it entirely).
    import tempfile

    from vuln_scanner.reporter import generate_markdown

    with tempfile.TemporaryDirectory() as out:
        md_path = os.path.join(out, "r.md")
        generate_markdown(
            findings, 1, 1, [{"full_name": "/x", "archived": False}],
            md_path, installed_info=[],
        )
        with open(md_path) as f:
            assert "| NOT_ANALYZED |" in f.read()

    # Regression: an unreadable dependency file (permission denied,
    # broken symlink) must also surface as NOT_ANALYZED, not be
    # silently dropped -- the same "looks clean" failure mode this test
    # guards against, just via OSError instead of a parse error.
    import stat

    with tempfile.TemporaryDirectory() as root:
        pkg = os.path.join(root, "package.json")
        with open(pkg, "w") as f:
            f.write('{"dependencies": {"axios": "1.14.1"}}')
        os.chmod(pkg, 0)
        try:
            unreadable_findings, _f2, _i2 = scan_local(root, None)
        finally:
            os.chmod(pkg, stat.S_IRUSR | stat.S_IWUSR)
    assert any(f["verdict"] == NOT_ANALYZED for f in unreadable_findings), (
        unreadable_findings
    )


def test_scan_local_passes_ecosystem_to_judge():
    """Regression guard (#16): scan_local's dependency-file judge() calls
    must pass the ecosystem of the file being parsed. Before the fix,
    judge(pkg, ver) was called with no ecosystem filter, so an npm/PyPI
    name collision could cross-contaminate verdicts."""
    import json
    import tempfile

    import vuln_scanner.local_scanner as local_scanner_mod

    real_judge = local_scanner_mod.judge
    calls = []

    def spy(pkg, ver, ecosystem=None):
        calls.append((pkg, ecosystem))
        return real_judge(pkg, ver, ecosystem=ecosystem)

    with tempfile.TemporaryDirectory() as root:
        with open(os.path.join(root, "package.json"), "w") as f:
            json.dump({"dependencies": {"axios": "1.14.1"}}, f)
        with open(os.path.join(root, "requirements.txt"), "w") as f:
            f.write("litellm==1.82.7\n")
        local_scanner_mod.judge = spy
        try:
            local_scanner_mod.scan_local(root, None)
        finally:
            local_scanner_mod.judge = real_judge

    eco_by_pkg = dict(calls)
    assert eco_by_pkg.get("axios") == "npm", calls
    assert eco_by_pkg.get("litellm") == "python", calls


def test_parsers_dict_carries_ecosystem():
    """Regression guard (#16 follow-up): the PARSERS backward-compat facade
    (dependency_parser.py) must tag its callables with .ecosystem too, or a
    legacy caller reading PARSERS[...] directly has no way to filter judge()
    by ecosystem the way get_parser() callers can."""
    from vuln_scanner.dependency_parser import PARSERS

    assert PARSERS["requirements"].ecosystem == "python"
    assert PARSERS["package.json"].ecosystem == "npm"


def test_reporter_passes_ecosystem_to_judge():
    """Regression guard (#16 follow-up): generate_markdown's installed-
    packages judge() call must pass ecosystem too -- code review on PR #22
    found this call site was missed by the initial fix."""
    import tempfile

    import vuln_scanner.reporter as reporter_mod

    real_judge = reporter_mod.judge
    calls = []

    def spy(pkg, ver, ecosystem=None):
        calls.append((pkg, ecosystem))
        return real_judge(pkg, ver, ecosystem=ecosystem)

    installed_info = [
        {"environment": "npm:proj", "ecosystem": "npm",
         "packages": {"axios": "1.14.1"}},
        {"environment": "venv", "ecosystem": "python", "python": "3.11",
         "packages": {"litellm": "1.82.7"}},
    ]
    reporter_mod.judge = spy
    try:
        with tempfile.TemporaryDirectory() as out:
            md_path = os.path.join(out, "r.md")
            reporter_mod.generate_markdown(
                [], 1, 1, [{"full_name": "/x", "archived": False}],
                md_path, installed_info=installed_info,
            )
    finally:
        reporter_mod.judge = real_judge

    eco_by_pkg = dict(calls)
    assert eco_by_pkg.get("axios") == "npm", calls
    assert eco_by_pkg.get("litellm") == "python", calls


def test_judge_worst_verdict_wins():
    """judge() must consult ALL owning threats (worst verdict wins) and
    honor the ecosystem filter -- npm and PyPI names collide."""
    # ecosystem filter: keyv is an npm threat
    assert judge("keyv", "6.0.0", ecosystem="npm")[0] == VULNERABLE
    assert judge("keyv", "6.0.0", ecosystem="python")[0] == SAFE
    assert judge("keyv", "6.0.0")[0] == VULNERABLE


def test_judge_basic_verdicts():
    """The keyv threat's 394 packages must all be exposed for
    parsing/judgment (regression: only the first direct_packages entry
    used to be exposed for a mass-worm threat), and judge() basics
    (VULNERABLE/SAFE, prerelease versions) must hold."""
    keyv = {t.name: t for t in get_all_threats()}["keyv"]
    assert len(keyv.all_packages) == 394, len(keyv.all_packages)
    assert judge("keyv", "6.0.0")[0] == "VULNERABLE"
    assert judge("keyv", "5.0.0")[0] == "SAFE"
    assert judge("@crawlee/core", "3.17.1-beta.80")[0] == "VULNERABLE"
    assert judge("cache-manager", "8.0.0")[0] == "SAFE"


def test_judge_no_version_collision_across_shared_threat():
    """Regression guard: with 394 packages sharing one threat, a version
    malicious for package A must not be flagged VULNERABLE for unrelated
    package B just because the version string happens to collide."""
    assert judge("@adminide-stack/clock-tik-browser", "1.81.0")[0] == "SAFE"
    assert judge("@adminide-stack/clock-tik-browser", "12.0.24")[0] == "VULNERABLE"
    assert judge("@7n/rules", "1.81.0")[0] == "VULNERABLE"


def test_package_lock_json_scoped_names():
    """Regression guard: scoped package names must survive lockfile
    parsing (package-lock.json v2/v3 strips everything before the last
    "/" naively if not handled)."""
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


# Shared expected result for the pnpm/yarn all-generations tests below:
# both lockfile families resolve the same four packages to the same
# versions once scoped/quoted/peer-suffix handling is correct.
_LOCK_TARGETS = {"@arv-bedrock/auth", "keyv", "react", "use-sync-external-store"}
_LOCK_EXPECTED = [
    ("@arv-bedrock/auth", "1.1.7"),
    ("keyv", "6.0.0"),
    ("react", "18.3.1"),
    ("use-sync-external-store", "1.2.2"),
]


def test_pnpm_lock_all_generations():
    """Regression guard (#6, N01): pnpm-lock.yaml v9 (current default)
    quotes scoped keys -- the closing quote used to leak into the
    extracted version, judging a vulnerable scoped package SAFE. Covers
    all three generations (real `pnpm install --lockfile-only` output,
    pnpm 7/8/11, names/versions substituted -- the malicious versions
    are unpublished so a lock for them can't be generated directly),
    plus the negative-space and dotted-name cases found while fixing it.
    """
    for gen in ("v5", "v6", "v9"):
        with open(_fixture(f"pnpm-lock-{gen}.yaml")) as f:
            parsed = parse_pnpm_lock(f.read(), _LOCK_TARGETS)
        # List (not set) equality: each package must be reported exactly
        # once (v9 repeats every package under `snapshots:`), scoped
        # quoting must not leak into versions, and `(peer)`/`_peer`
        # suffixes must be stripped.
        assert parsed == _LOCK_EXPECTED, (gen, parsed)

    # Negative space: keys outside the `packages:` section must not be
    # reported -- `overrides:` names a version that is not necessarily
    # installed, `snapshots:` would double-count. (Synthetic snippet: a
    # does-not-detect probe, not lockfile fixture data.)
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


def test_yarn_lock_all_generations():
    """Regression guard (#8, N02): yarn berry (v2+) writes
    `version: 1.1.7` (colon-separated, unquoted) instead of classic's
    `version "1.1.7"` -- the parser used to read berry lockfiles as
    completely empty (not even WARNING). Real `yarn install` output
    (yarn 1.22 / yarn 4.6), names/versions substituted, plus the
    workspace-placeholder and virtual-dedup cases found while fixing it.
    """
    for gen in ("classic", "berry"):
        with open(_fixture(f"yarn-{gen}.lock")) as f:
            yarn_content = f.read()
        parsed = parse_yarn_lock(yarn_content, _LOCK_TARGETS)
        assert parsed == _LOCK_EXPECTED, (gen, parsed)

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


def test_single_direct_package_threat():
    """Regression guard: single direct_package threats (as opposed to
    keyv's 394-package mass worm) still work end to end."""
    axios = {t.name: t for t in get_all_threats()}["axios"]
    assert axios.all_packages == {"axios", "plain-crypto-js"}
    assert judge("axios", "1.14.1")[0] == "VULNERABLE"
    assert judge("plain-crypto-js", None)[0] == "VULNERABLE"


def main():
    test_judge_basic_verdicts()
    test_judge_no_version_collision_across_shared_threat()
    test_package_lock_json_scoped_names()
    test_pnpm_lock_all_generations()
    test_yarn_lock_all_generations()
    test_single_direct_package_threat()
    test_enrich_does_not_flip_verdicts()
    test_enrich_most_severe_lock_version()
    test_semver_ranges_never_assert_safe()
    test_python_parsers_preserve_range_operators()
    test_disk_scan_three_layouts()
    test_disk_scan_no_false_positive_from_subtree()
    test_enrich_findings_handles_multi_version_installed()
    test_not_analyzed_never_looks_clean()
    test_scan_local_passes_ecosystem_to_judge()
    test_parsers_dict_carries_ecosystem()
    test_reporter_passes_ecosystem_to_judge()
    test_judge_worst_verdict_wins()

    print("OK")


if __name__ == "__main__":
    main()

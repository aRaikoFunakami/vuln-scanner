"""Scan local directories for supply chain attack vulnerabilities.

Generic scanner that delegates ecosystem-specific logic to threat modules.
"""

import glob
import json
import os

from vuln_scanner.threats import (
    get_all_threats,
    get_all_file_patterns_glob,
    get_parser,
    judge,
)
from vuln_scanner.threats.base import (
    NOT_ANALYZED,
    VULNERABLE,
    file_too_large,
    is_within,
)

# Dependency files whose content must be valid JSON; a JSONDecodeError
# here is a genuine "could not analyze" signal, not a coincidental zero
# match (issue #11).
_JSON_DEPENDENCY_BASENAMES = {"package.json", "package-lock.json", "Pipfile.lock"}


def find_dependency_files(root_dir):
    """Find all dependency files under root_dir.

    Returns:
        List of absolute file paths.
    """
    patterns = get_all_file_patterns_glob()
    found = []
    for pattern in patterns:
        found.extend(glob.glob(os.path.join(root_dir, pattern), recursive=True))
    # Exclude files inside node_modules
    found = [f for f in found if "/node_modules/" not in f and "\\node_modules\\" not in f]
    # Reject anything reached through a symlink escaping the scan root:
    # `**` follows directory symlinks, so a hostile repo could point the
    # scanner at files anywhere on the host (issue #28).
    found = [f for f in found if is_within(f, root_dir)]
    # Deduplicate and sort
    return sorted(set(found))


def scan_local(root_dir, logger=None):
    """Scan a local directory for vulnerable dependencies.

    Returns:
        (findings, files_scanned, installed_info) tuple.
        installed_info is a list of dicts describing installed packages per environment.
    """
    findings = []
    root_dir = os.path.abspath(root_dir)
    threats = get_all_threats()

    # 0. List all subdirectories for audit trail
    subdirs = []
    try:
        subdirs = sorted([
            d for d in os.listdir(root_dir)
            if os.path.isdir(os.path.join(root_dir, d)) and not d.startswith(".")
        ])
    except OSError:
        pass
    if logger and subdirs:
        logger.info(f"  サブディレクトリ一覧 ({len(subdirs)}件): {subdirs}")

    # 1. Scan dependency files
    dep_files = find_dependency_files(root_dir)
    if logger:
        logger.info(f"  依存ファイル {len(dep_files)}件検出")
        for f in dep_files:
            logger.info(f"    - {os.path.relpath(f, root_dir)}")

        # Report directories with no dependency files
        if subdirs:
            dirs_with_deps = set()
            for f in dep_files:
                rel = os.path.relpath(f, root_dir)
                top_dir = rel.split(os.sep)[0]
                dirs_with_deps.add(top_dir)
            dirs_without = [d for d in subdirs if d not in dirs_with_deps]
            if dirs_without:
                logger.info(f"  依存ファイルなし ({len(dirs_without)}件): {dirs_without}")

    def not_analyzed(rel_path, reason):
        # "not analyzed" must never look like "clean" -- give it its own
        # finding rather than silently `continue`ing past the file
        # (CLAUDE.md レビュー観点2, issue #11).
        findings.append({
            "repo": root_dir,
            "file_path": rel_path,
            "package": "(unknown)",
            "version": None,
            "verdict": NOT_ANALYZED,
            "note": reason,
            "source": "dependency_file",
        })
        if logger:
            logger.warning(f"    {rel_path}: {reason} → NOT_ANALYZED")

    for file_path in dep_files:
        rel_path = os.path.relpath(file_path, root_dir)
        parser = get_parser(file_path)
        if not parser:
            # Recognized as a dependency file (matched a threat's glob
            # pattern) but no ecosystem module understands its format
            # (e.g. a future lockfile generation).
            not_analyzed(rel_path, "未対応の依存ファイル形式のため解析できませんでした")
            continue

        if file_too_large(file_path):
            # A hostile repo could ship a multi-GB file named like a
            # manifest; reading it whole would OOM the scanner (issue #28).
            not_analyzed(rel_path, "ファイルサイズが上限を超えるため解析をスキップしました")
            continue

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError as e:
            not_analyzed(rel_path, f"ファイルを読み込めませんでした（{e.__class__.__name__}）")
            continue

        if logger:
            logger.debug(f"    {rel_path}: パース中 ({len(content)} bytes)")

        # ponytail: NOT_ANALYZED currently only covers "no parser" and
        # "JSON parse failure" -- a non-JSON lockfile whose CONTENT is
        # in an unrecognized sub-format (e.g. a future yarn.lock/
        # pnpm-lock.yaml variant) still silently parses to 0 matches.
        # Not covered because "0 packages found" is also the normal,
        # correct output for a genuinely dependency-free file, and a
        # blanket "non-empty file, 0 total entries" heuristic would
        # false-positive on those. Revisit if a real format-quirk case
        # like that shows up (see issue #11 discussion).
        basename = os.path.basename(file_path)
        if basename in _JSON_DEPENDENCY_BASENAMES and content.strip():
            try:
                json.loads(content)
            except (json.JSONDecodeError, ValueError):
                not_analyzed(rel_path, "JSON として解析できませんでした（破損または不正な形式）")
                continue

        packages = parser(content)
        for pkg_name, version in packages:
            verdict, note = judge(pkg_name, version, ecosystem=parser.ecosystem)  # type: ignore[attr-defined]
            findings.append({
                "repo": root_dir,
                "file_path": rel_path,
                "package": pkg_name,
                "version": version,
                "verdict": verdict,
                "note": note,
                "source": "dependency_file",
            })
            if logger:
                logger.debug(f"    検出: {pkg_name}=={version or '(未指定)'} → {verdict}")

    # 2. Delegate installed-package checks to each threat
    installed_info = []
    for threat in threats:
        threat_installed = threat.check_installed(root_dir, dep_files, logger)
        for env_entry in threat_installed:
            installed_info.append(env_entry)
            for pkg, ver_or_vers in env_entry["packages"].items():
                # npm can have several on-disk copies of one package
                # (hoisted + pnpm-store/nested, issue #10); python has
                # exactly one per venv entry
                versions = (
                    ver_or_vers if isinstance(ver_or_vers, list) else [ver_or_vers]
                )
                for ver in versions:
                    env_label = env_entry["environment"]
                    ecosystem = env_entry.get("ecosystem", "")
                    verdict, note = judge(pkg, ver, ecosystem=ecosystem or None)
                    if ecosystem == "npm":
                        note = f"npm インストール済み (dir: {env_label.removeprefix('npm:')})"
                        file_path_label = f"(npm installed: {env_label.removeprefix('npm:')})"
                        source = "npm_list"
                    else:
                        if env_label == "system":
                            note = f"インストール済み (system python: {env_entry['python']})"
                            file_path_label = "(installed)"
                        else:
                            note = f"インストール済み (venv: {env_label})"
                            file_path_label = f"(installed: {env_label})"
                        source = "pip_freeze"
                    findings.append({
                        "repo": root_dir,
                        "file_path": file_path_label,
                        "package": pkg,
                        "version": ver,
                        "verdict": verdict,
                        "note": note,
                        "source": source,
                    })
                    if logger:
                        logger.info(f"    インストール済み: {pkg}=={ver} → {verdict}")

    # 3. Check for malicious directories (e.g. node_modules/plain-crypto-js)
    for threat in threats:
        malicious_dirs = threat.find_malicious_dirs(root_dir, logger)
        for malicious_dir in malicious_dirs:
            rel_path = os.path.relpath(malicious_dir, root_dir)
            findings.append({
                "repo": root_dir,
                "file_path": rel_path,
                "package": os.path.basename(malicious_dir),
                "version": None,
                "verdict": VULNERABLE,
                "note": f"悪意あるパッケージ {os.path.basename(malicious_dir)} を検出",
                "source": "node_modules",
            })

    # NOTE: malware-artifact probing is deliberately NOT done here.
    # check_artifacts inspects absolute HOST paths (e.g. /tmp/ld.py) that
    # have nothing to do with the directory being scanned, so attributing
    # a hit to this repo -- and running it once per scanned dir -- was
    # wrong (issue #29). It now runs once at host level in
    # scan_host_artifacts(), reported separately from per-repo verdicts.

    # 5. Enrich findings (e.g. fill in missing versions from lockfiles/installed).
    # Once per ecosystem: enrichment has no per-threat state and judges
    # cross-threat, so running it per threat repeats identical work
    # (lockfile I/O and log lines scale with threats.json entries).
    enriched_ecosystems = set()
    for threat in threats:
        if threat.ecosystem in enriched_ecosystems:
            continue
        enriched_ecosystems.add(threat.ecosystem)
        threat.enrich_findings(findings, installed_info, dep_files, root_dir, logger)

    return findings, len(dep_files), installed_info


# Sentinel repo label for host-level (not repo-scoped) findings.
HOST_REPO = "(host)"


def scan_host_artifacts(logger=None):
    """Probe host-level malware artifacts once, across all threats.

    These paths (e.g. ``/tmp/ld.py``) are properties of the MACHINE, not
    of any scanned repo, so they are reported with ``repo=HOST_REPO`` and
    source ``malware_artifact``, and the caller keeps them out of the
    per-repo VULNERABLE exit-code gate -- a world-writable artifact path
    must not non-deterministically fail every repo's CI (issue #29).

    Returns a list of finding dicts (possibly empty).
    """
    findings = []
    seen = set()
    for threat in get_all_threats():
        for artifact in threat.check_artifacts(logger):
            path = artifact["path"]
            if path in seen:
                continue
            seen.add(path)
            findings.append({
                "repo": HOST_REPO,
                "file_path": path,
                "package": "(malware artifact)",
                "version": None,
                "verdict": VULNERABLE,
                "note": (
                    f"ホスト上でマルウェア痕跡を検出 ({artifact['platform']}) "
                    "— スキャン対象リポジトリとは無関係な参考情報"
                ),
                "source": "malware_artifact",
            })
    return findings

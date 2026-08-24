"""Scan local directories for supply chain attack vulnerabilities.

Generic scanner that delegates ecosystem-specific logic to threat modules.
"""

import glob
import os

from vuln_scanner.threats import (
    get_all_threats,
    get_all_file_patterns_glob,
    get_parser,
    judge,
)
from vuln_scanner.threats.base import VULNERABLE


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

    for file_path in dep_files:
        parser = get_parser(file_path)
        if not parser:
            continue

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            continue

        rel_path = os.path.relpath(file_path, root_dir)
        if logger:
            logger.debug(f"    {rel_path}: パース中 ({len(content)} bytes)")

        packages = parser(content)
        for pkg_name, version in packages:
            verdict, note = judge(pkg_name, version)
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
                    verdict, note = judge(pkg, ver)
                    env_label = env_entry["environment"]
                    ecosystem = env_entry.get("ecosystem", "")
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

    # 4. Check for malware artifacts
    for threat in threats:
        artifacts = threat.check_artifacts(logger)
        for artifact in artifacts:
            findings.append({
                "repo": root_dir,
                "file_path": artifact["path"],
                "package": "(malware artifact)",
                "version": None,
                "verdict": VULNERABLE,
                "note": f"マルウェア痕跡を検出 ({artifact['platform']})",
                "source": "malware_artifact",
            })

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

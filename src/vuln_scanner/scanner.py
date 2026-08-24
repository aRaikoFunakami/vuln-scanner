#!/usr/bin/env python3
"""Supply chain attack scanner.

Scans GitHub repositories and/or local directories for:
- LiteLLM (Python/PyPI): v1.82.7, v1.82.8
- axios (npm): v1.14.1, v0.30.4 + plain-crypto-js
"""

import argparse
import logging
import sys
import os
from datetime import datetime
from importlib.metadata import PackageNotFoundError, version

from vuln_scanner.threats import NOT_ANALYZED, VULNERABLE, get_parser, judge
from vuln_scanner.reporter import generate_csv, generate_json, generate_markdown, print_summary

try:
    __version__ = version("vuln-scanner")
except PackageNotFoundError:
    __version__ = "unknown"


def build_output_dir(scan_label):
    """Build timestamped output directory under logs/.

    Returns:
        Absolute path to the output directory (e.g., logs/20260330_180000_JST_github_all/).
    """
    now = datetime.now().astimezone()
    tz_abbr = now.strftime("%Z")  # e.g. "JST", "PST"
    timestamp = now.strftime(f"%Y%m%d_%H%M%S_{tz_abbr}")
    dir_name = f"{timestamp}_{scan_label}"
    out_dir = os.path.join("logs", dir_name)
    os.makedirs(out_dir, exist_ok=True)
    return out_dir


def setup_logging(output_dir, scan_label):
    """Configure logging to both console and file.

    Args:
        output_dir: Output directory where all files including log are saved.
        scan_label: Descriptive label for the scan.
    """
    os.makedirs(output_dir, exist_ok=True)
    log_path = os.path.join(output_dir, f"{scan_label}.log")

    logger = logging.getLogger("scanner")
    logger.setLevel(logging.DEBUG)

    # File handler — full debug log as evidence
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(fh)

    # Console handler — info level
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(ch)

    logger.info(f"調査ログ: {log_path}")
    return logger, log_path


def scan_github_repo(owner_repo, default_branch, logger):
    """Scan a single GitHub repository for vulnerable dependencies."""
    from vuln_scanner.github_client import get_dependency_files, get_file_content

    findings = []
    dep_files = get_dependency_files(owner_repo, default_branch)
    if not dep_files:
        logger.debug(f"  {owner_repo}: 依存ファイルなし")
        return findings, 0

    logger.debug(f"  {owner_repo}: 依存ファイル {len(dep_files)}件 — {dep_files}")

    for file_path in dep_files:
        parser = get_parser(file_path)
        if not parser:
            logger.debug(f"    {file_path}: パーサーなし (skip)")
            continue

        content = get_file_content(owner_repo, file_path)
        if not content:
            logger.debug(f"    {file_path}: 内容取得失敗 (skip)")
            continue

        logger.debug(f"    {file_path}: パース中 ({len(content)} bytes)")
        packages = parser(content)
        for pkg_name, version in packages:
            verdict, note = judge(pkg_name, version)
            findings.append({
                "repo": owner_repo,
                "file_path": file_path,
                "package": pkg_name,
                "version": version,
                "verdict": verdict,
                "note": note,
                "source": "github",
            })
            logger.debug(f"    検出: {pkg_name}=={version or '(未指定)'} → {verdict}")

    return findings, len(dep_files)


def run_github_scan(args, logger):
    """Run GitHub repository scan."""
    from vuln_scanner.github_client import (
        check_auth, get_user_repos, get_specific_user_repos, get_org_repos,
    )

    logger.info("=== GitHub リポジトリスキャン ===")
    logger.info("認証状態を確認中...")
    username = check_auth()
    logger.info(f"認証ユーザー: {username}")
    logger.debug(f"GitHub認証確認完了: user={username}")

    repos_filter = args.repos.split(",") if args.repos else None
    logger.info("リポジトリ一覧を取得中...")

    if args.user:
        target_user = args.user
        logger.info(f"対象ユーザー: {target_user}")
        repos = get_specific_user_repos(target_user, repos_filter)
    elif args.org:
        target_org = args.org
        logger.info(f"対象 Organization: {target_org}")
        repos = get_org_repos(target_org, repos_filter)
    else:
        repos = get_user_repos(username, repos_filter)

    logger.info(f"対象リポジトリ数: {len(repos)}")
    logger.debug(f"リポジトリ一覧: {[r['full_name'] for r in repos]}")

    if not repos:
        logger.info("スキャン対象のリポジトリがありません。")
        return [], 0, repos

    all_findings = []
    total_files = 0

    for i, repo in enumerate(repos, 1):
        name = repo["full_name"]
        branch = repo["default_branch"]
        archived = repo.get("archived", False)

        if archived:
            logger.info(f"  [{i}/{len(repos)}] {name} (archived, skip)")
            continue

        logger.info(f"  [{i}/{len(repos)}] {name} ...")
        logger.debug(f"  {name}: スキャン開始 (branch={branch})")

        findings, files_scanned = scan_github_repo(name, branch, logger)
        total_files += files_scanned

        if findings:
            logger.info(f"    → 検出: {len(findings)}件")
            all_findings.extend(findings)
        else:
            logger.info(f"    → OK")

    return all_findings, total_files, repos


def run_local_scan(args, logger):
    """Run local directory scan."""
    from vuln_scanner.local_scanner import scan_local

    dirs = [d.strip() for d in args.local.split(",")]
    logger.info("=== ローカルディレクトリスキャン ===")

    all_findings = []
    total_files = 0
    all_installed = []
    scanned_dirs = []

    for d in dirs:
        abs_dir = os.path.abspath(d)
        if not os.path.isdir(abs_dir):
            logger.info(f"  {abs_dir}: ディレクトリが存在しません (skip)")
            continue

        logger.info(f"  スキャン中: {abs_dir}")
        findings, files_scanned, installed_info = scan_local(abs_dir, logger)
        total_files += files_scanned
        all_findings.extend(findings)
        all_installed.extend(installed_info)
        scanned_dirs.append(abs_dir)

    # Build pseudo-repo list for report compatibility
    local_repos = [{"full_name": d, "archived": False} for d in scanned_dirs]

    return all_findings, total_files, local_repos, all_installed


def main():
    parser = argparse.ArgumentParser(
        description="サプライチェーン攻撃スキャナー — LiteLLM (Python) + axios (npm) 対応"
    )
    parser.add_argument(
        "--version", action="version", version=f"vuln-scanner {__version__}"
    )
    parser.add_argument(
        "--output-dir",
        help="出力ディレクトリ（指定時はこのパスに直接出力。未指定時は logs/YYYYMMDD_HHMMSS_TZ_label/ に自動生成）",
    )
    parser.add_argument(
        "--repos",
        help="GitHub スキャン対象リポジトリ (カンマ区切り, 例: org/repo1,user/repo2)",
    )
    parser.add_argument(
        "--user",
        help="指定ユーザーのリポジトリをスキャン (例: aRaikoFunakami)",
    )
    parser.add_argument(
        "--org",
        help="指定 Organization のリポジトリをスキャン (例: access-company)",
    )
    parser.add_argument(
        "--local",
        help="ローカルスキャン対象ディレクトリ (カンマ区切り, 例: ./project1,./project2)",
    )
    args = parser.parse_args()

    if args.user and args.org:
        parser.error("--user と --org は同時に指定できません")

    # Determine if GitHub scan should run
    has_github_args = args.repos is not None or args.user is not None or args.org is not None
    if not has_github_args and not args.local:
        # Default: GitHub scan all repos
        args._github_mode = True
    else:
        args._github_mode = has_github_args or (not args.local)

    # Build descriptive scan label
    label_parts = []
    if args._github_mode:
        if args.user:
            label_parts.append(f"user_{args.user}")
        elif args.org:
            label_parts.append(f"org_{args.org}")
        elif args.repos:
            first_repo = args.repos.split(",")[0].strip().replace("/", "_")
            label_parts.append(f"github_{first_repo}")
        else:
            label_parts.append("github_all")
    if args.local:
        first_dir = os.path.basename(os.path.abspath(args.local.split(",")[0].strip()))
        label_parts.append(f"local_{first_dir}")
    scan_label = "_".join(label_parts) or "supply_chain_scan"

    # --output-dir 指定があればそれを最優先、なければ logs/ 配下に自動生成
    if args.output_dir:
        output_dir = args.output_dir
        os.makedirs(output_dir, exist_ok=True)
    else:
        output_dir = build_output_dir(scan_label)

    logger, log_path = setup_logging(output_dir, scan_label)

    all_findings = []
    total_files = 0
    all_repos = []
    all_installed = []

    # GitHub scan
    if args._github_mode:
        gh_findings, gh_files, gh_repos = run_github_scan(args, logger)
        all_findings.extend(gh_findings)
        total_files += gh_files
        all_repos.extend(gh_repos)

    # Local scan
    if args.local:
        local_findings, local_files, local_repos, installed = run_local_scan(args, logger)
        all_findings.extend(local_findings)
        total_files += local_files
        all_repos.extend(local_repos)
        all_installed.extend(installed)

    # Output results
    csv_path = os.path.join(output_dir, "scan_results.csv")
    json_path = os.path.join(output_dir, "scan_results.json")
    md_path = os.path.join(output_dir, "scan_report.md")

    generate_csv(all_findings, csv_path)
    generate_json(all_findings, json_path)
    generate_markdown(
        all_findings, len(all_repos), total_files, all_repos, md_path,
        installed_info=all_installed,
    )
    print_summary(all_findings, len(all_repos), total_files)

    logger.info(f"\n出力ファイル ({output_dir}/):")
    logger.info(f"  レポート (Markdown): {md_path}")
    logger.info(f"  結果 (CSV):          {csv_path}")
    logger.info(f"  結果 (JSON):         {json_path}")
    logger.info(f"  調査ログ:            {log_path}")

    # CI gate.  Exit codes: 0 = clean, 1 = VULNERABLE findings,
    # 2 = operational error (argparse usage errors and gh auth failures
    # already use 2), 3 = dependency files were found but could not be
    # analyzed (judgment withheld -- issue #11), and no VULNERABLE
    # finding overrode that. VULNERABLE always wins: a real detection
    # must never be masked by an unrelated parse failure elsewhere.
    if any(f["verdict"] == VULNERABLE for f in all_findings):
        return 1
    if any(f["verdict"] == NOT_ANALYZED for f in all_findings):
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())

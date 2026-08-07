"""Report generation in CSV, JSON, Markdown, and console formats.

All threat-specific text is sourced from registered threat modules.
"""

import csv
import json
import os
from collections import Counter
from datetime import datetime

from vuln_scanner.threats import get_all_threats, judge


CSV_HEADERS = [
    "リポジトリ",
    "ファイルパス",
    "パッケージ名",
    "バージョン",
    "判定",
    "備考",
]


def generate_csv(findings, output_path):
    """Write findings to CSV file."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADERS)
        for finding in findings:
            writer.writerow([
                finding["repo"],
                finding["file_path"],
                finding["package"],
                finding["version"] or "",
                finding["verdict"],
                finding["note"],
            ])
    print(f"CSV output: {output_path}")


def generate_json(findings, output_path):
    """Write findings to JSON file."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    report = {
        "scan_date": datetime.now().isoformat(),
        "total_findings": len(findings),
        "findings": findings,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"JSON output: {output_path}")


def generate_markdown(findings, total_repos, total_files, scanned_repos, output_path,
                      installed_info=None):
    """Write investigation report in Markdown format."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    verdicts = Counter(f["verdict"] for f in findings)
    installed_info = installed_info or []
    threats = get_all_threats()

    # Determine scan mode
    has_github = any("/" in r.get("full_name", "") and not r["full_name"].startswith("/")
                     for r in scanned_repos)
    has_local = any(r["full_name"].startswith("/") for r in scanned_repos)
    if has_github and has_local:
        scan_target = "GitHub リポジトリ + ローカルディレクトリ"
    elif has_local:
        scan_target = "ローカルディレクトリ"
    else:
        scan_target = "GitHub リポジトリ（個人）"

    lines = []
    lines.append("# サプライチェーン攻撃 点検レポート")
    lines.append("")
    lines.append("## 1. 調査概要")
    lines.append("")
    lines.append("| 項目 | 内容 |")
    lines.append("|------|------|")
    lines.append(f"| 調査日時 | {now} |")
    lines.append(f"| 調査対象 | {scan_target} |")
    lines.append(f"| 調査対象数 | {total_repos} |")
    lines.append(f"| スキャン済みファイル数 | {total_files} |")
    lines.append(f"| 検出件数 | {len(findings)} |")
    for threat in threats:
        direct_pkgs = sorted(threat.direct_packages)
        if len(direct_pkgs) > 1:
            lines.append(
                f"| 脆弱バージョン ({threat.name}) | {len(direct_pkgs)}パッケージ"
                "（詳細は「調査対象パッケージ」セクション参照） |"
            )
        else:
            vers = ", ".join(sorted(threat.vulnerable_versions))
            lines.append(f"| 脆弱バージョン ({threat.name}) | {direct_pkgs[0]} {vers} |")
    lines.append("")

    lines.append("## 2. 判定基準")
    lines.append("")
    lines.append("| 判定 | 意味 |")
    lines.append("|------|------|")
    lines.append("| VULNERABLE | 脆弱バージョンの使用、または悪意あるパッケージの検出 |")
    lines.append("| SAFE | 対象パッケージを使用しているが安全なバージョン |")
    lines.append("| WARNING | バージョン未指定で使用（脆弱バージョンがインストールされた可能性あり） |")
    lines.append("| CHECK_INDIRECT | 間接依存として脆弱パッケージを利用するパッケージを検出（手動確認推奨） |")
    lines.append("")

    lines.append("## 3. 判定別サマリー")
    lines.append("")
    if findings:
        lines.append("| 判定 | 件数 |")
        lines.append("|------|------|")
        for verdict in ["VULNERABLE", "WARNING", "CHECK_INDIRECT", "SAFE"]:
            if verdicts.get(verdict, 0) > 0:
                lines.append(f"| {verdict} | {verdicts[verdict]} |")
    else:
        lines.append("該当なし — 対象パッケージの使用は検出されませんでした。")
    lines.append("")

    # Use a running section counter
    sec = 3

    # VULNERABLE details
    vulns = [f for f in findings if f["verdict"] == "VULNERABLE"]
    if vulns:
        sec += 1
        lines.append(f"## {sec}. 脆弱バージョン検出（要即時対応）")
        lines.append("")
        lines.append("| リポジトリ | ファイル | パッケージ | バージョン |")
        lines.append("|-----------|---------|-----------|-----------|")
        for v in vulns:
            lines.append(f"| {v['repo']} | {v['file_path']} | {v['package']} | {v['version']} |")
        lines.append("")
        lines.append("> **対応必須**: 上記のシステムでは、アクセス可能だった全認証情報（SSH鍵、AWS/GCP/Azure クレデンシャル、npm/GitHubトークン、.env 内 API キー等）の即時ローテーションと、安全なバージョンへの移行が必要です。")
        lines.append("> axios 脆弱バージョンの場合は `node_modules` と `package-lock.json` を削除し `npm ci` でクリーン再構築してください。")
        lines.append("")

    # All findings detail
    if findings:
        sec += 1
        lines.append(f"## {sec}. 検出結果一覧")
        lines.append("")
        lines.append("| リポジトリ | ファイルパス | パッケージ名 | バージョン | 判定 | 備考 |")
        lines.append("|-----------|------------|------------|-----------|------|------|")
        for f in findings:
            ver = f["version"] or "（未指定）"
            lines.append(f"| {f['repo']} | {f['file_path']} | {f['package']} | {ver} | {f['verdict']} | {f['note']} |")
        lines.append("")

    # Installed packages section (local scan only)
    if installed_info:
        sec += 1
        lines.append(f"## {sec}. インストール済みパッケージ（実環境）")
        lines.append("")
        lines.append("ローカル環境で実際にインストールされているパッケージのバージョンです。")
        lines.append("")

        # Group by ecosystem
        for threat in threats:
            eco = threat.ecosystem
            eco_envs = [e for e in installed_info if e.get("ecosystem") == eco]
            if not eco_envs:
                continue
            if eco == "python":
                lines.append("### Python 環境（pip freeze / uv pip freeze）")
            elif eco == "npm":
                lines.append("### npm 環境（npm list / node_modules）")
            else:
                lines.append(f"### {eco} 環境")
            lines.append("")
            for env in eco_envs:
                if eco == "npm":
                    dir_label = env["environment"].removeprefix("npm:")
                    lines.append(f"#### `{dir_label}`")
                else:
                    lines.append(f"#### `{env['environment']}`")
                    lines.append(f"- Python: `{env['python']}`")
                lines.append("")
                lines.append("| パッケージ名 | インストール済みバージョン | 判定 |")
                lines.append("|------------|----------------------|------|")
                for pkg, ver in env["packages"].items():
                    verdict, _ = judge(pkg, ver)
                    lines.append(f"| {pkg} | {ver} | {verdict} |")
                lines.append("")

    # Scanned repo list
    sec += 1
    lines.append(f"## {sec}. スキャン対象一覧")
    lines.append("")
    lines.append(f"全 {total_repos} 件をスキャンしました。")
    lines.append("")
    lines.append("<details>")
    lines.append("<summary>一覧（クリックで展開）</summary>")
    lines.append("")
    for repo in scanned_repos:
        name = repo["full_name"]
        archived = repo.get("archived", False)
        suffix = " (archived, skipped)" if archived else ""
        lines.append(f"- `{name}`{suffix}")
    lines.append("")
    lines.append("</details>")
    lines.append("")

    # Methodology section
    sec += 1
    lines.append(f"## {sec}. 調査方法")
    lines.append("")
    lines.append("### 調査背景")
    lines.append("")
    for threat in threats:
        lines.extend(threat.report_background())
        lines.append("")

    lines.append("### 調査対象パッケージ")
    lines.append("")
    for threat in threats:
        lines.extend(threat.report_target_packages())
        lines.append("")

    lines.append("### 脆弱バージョン")
    lines.append("")
    for threat in threats:
        lines.extend(threat.report_vulnerable_versions())
        lines.append("")

    # Malware artifacts (only if any threat provides them)
    malware_lines = []
    for threat in threats:
        ml = threat.report_malware_artifacts()
        if ml:
            malware_lines.extend(ml)
    if malware_lines:
        lines.extend(malware_lines)
        lines.append("")

    if has_github:
        lines.append("### GitHub リポジトリスキャン手順")
        lines.append("")
        lines.append("1. **リポジトリ一覧取得**: `gh api /user/repos --paginate` により認証ユーザーの全リポジトリを取得")
        lines.append("2. **ファイルツリー取得**: 各リポジトリに対して `gh api /repos/{owner}/{repo}/git/trees/{branch}?recursive=1` でファイル一覧を取得")
        lines.append("3. **依存ファイル特定**: 登録済み脅威モジュールのファイルパターンに一致するものを抽出")
        lines.append("4. **ファイル内容取得**: `gh api /repos/{owner}/{repo}/contents/{path}` で Base64 エンコードされた内容を取得・デコード")
        lines.append("5. **パッケージ検出**: 各ファイル形式に応じたパーサーで対象パッケージの使用有無とバージョンを抽出")
        lines.append("")
        lines.append("> **GitHub スキャンの制限事項**: lockfile（`poetry.lock`, `Pipfile.lock`, `package-lock.json`, `yarn.lock` 等）が")
        lines.append("> リポジトリに含まれていない場合、**推移的依存（他のパッケージ経由で間接的にインストールされる脆弱パッケージ）は検出できません**。")
        lines.append("> 依存ファイルに直接記載されたパッケージと、`indirect_packages` として事前登録されたパッケージのみが検出対象です。")
        lines.append("> より確実な調査には、対象リポジトリを `git clone` してローカルスキャン（`--local`）を実行してください。")
        lines.append("")
        lines.append("> **安全性**: 全 API 呼び出しは `gh` CLI 経由の GET リクエストのみです。")
        lines.append("> ツール内部のバリデーション（`_validate_gh_args`）により、")
        lines.append("> 書き込み操作（POST/PUT/PATCH/DELETE）、許可リスト外の API パス、")
        lines.append("> 許可リスト外のサブコマンド（`gh repo delete` 等）は実行できません。")
        lines.append("")

    if has_local:
        lines.append("### ローカルディレクトリスキャン手順")
        lines.append("")
        lines.append("1. **依存ファイル検索**: 指定ディレクトリ配下を再帰的に走査し、全脅威モジュールのパターンに一致するファイルを収集")
        lines.append("2. **ファイル内容パース**: 各ファイルを直接読み取り、対象パッケージの使用有無とバージョンを抽出")
        lines.append("3. **インストール済みパッケージ確認**: 各脅威モジュールがエコシステム固有のチェックを実行")
        lines.append("   - Python: `pip freeze` / `uv pip freeze` によるシステム Python と仮想環境の確認")
        lines.append("   - npm: `npm list` および `node_modules/` 内のパッケージ直接確認")
        lines.append("4. **悪意あるディレクトリ検索**: 各脅威モジュールが既知の悪意あるパッケージのディレクトリを検索")
        lines.append("5. **マルウェア痕跡確認**: 各脅威モジュールが OS 別の既知マルウェアファイルパスを確認")
        lines.append("6. **バージョン補完**: lockfile や実環境の情報で未指定バージョンを補完")
        lines.append("")
        lines.append("> **ローカルスキャンの利点**: GitHub スキャンとは異なり、ローカル環境では実際にインストールされた")
        lines.append("> パッケージとバージョンを直接確認できます。lockfile がないプロジェクトでも、`pip freeze` や")
        lines.append("> `node_modules/` から推移的依存を含む正確なバージョン情報を取得できるため、")
        lines.append("> **間接的にインストールされた脆弱パッケージも検出可能**です。")
        lines.append("")

    lines.append("### 判定ロジック")
    lines.append("")
    lines.append("| 条件 | 判定 |")
    lines.append("|------|------|")
    for threat in threats:
        lines.extend(threat.report_judgment_rows())
    lines.append("| 対象パッケージのバージョンが上記以外で明示されている | SAFE |")
    lines.append("| 対象パッケージがバージョン未指定で記載されている | WARNING |")
    lines.append("")

    lines.append("### エビデンス")
    lines.append("")
    lines.append("- 本レポートと同一ディレクトリに出力された調査ログ（`scan_*.log`）に、")
    lines.append("  各リポジトリ/ディレクトリのスキャン過程がタイムスタンプ付きで記録されています。")
    lines.append("- 同ディレクトリの CSV / JSON ファイルに、検出結果の構造化データが含まれています。")
    lines.append("")

    lines.append("---")
    lines.append(f"*本レポートは vuln-scanner により自動生成されました（{now}）*")
    lines.append("")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Markdown output: {output_path}")


def print_summary(findings, total_repos, total_files):
    """Print a summary to console."""
    print("\n" + "=" * 60)
    print("サプライチェーン攻撃 点検結果サマリー")
    print("=" * 60)
    print(f"スキャン日時: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"スキャン対象リポジトリ数: {total_repos}")
    print(f"スキャン対象ファイル数: {total_files}")
    print(f"検出件数: {len(findings)}")

    if not findings:
        print("\n✓ 対象パッケージの使用は検出されませんでした。")
        print("=" * 60)
        return

    # Count by verdict
    verdicts = Counter(f["verdict"] for f in findings)
    print("\n判定別件数:")
    for verdict, count in sorted(verdicts.items()):
        mark = "!!" if verdict == "VULNERABLE" else "  "
        print(f"  {mark} {verdict}: {count}件")

    # Show VULNERABLE details
    vulns = [f for f in findings if f["verdict"] == "VULNERABLE"]
    if vulns:
        print("\n*** 脆弱バージョン検出 ***")
        for v in vulns:
            print(f"  {v['repo']} / {v['file_path']}")
            print(f"    {v['package']}=={v['version']} → 即時対応が必要")

    print("=" * 60)

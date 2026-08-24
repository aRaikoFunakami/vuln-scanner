# vuln-scanner

サプライチェーン攻撃の影響調査を自動化するツール。
GitHub リポジトリおよびローカル開発環境を対象に、脆弱なパッケージの使用有無を検出する。

脅威定義は `threats.json` で管理されており、新しい脅威の追加やバージョン更新はコード変更不要。

## 対応する脅威

| 脅威 | エコシステム | 脆弱バージョン | 概要 | 調査基準日 | 参照 |
|------|------------|--------------|------|-----------|------|
| LiteLLM | Python (PyPI) | 1.82.7, 1.82.8 | SSH鍵・クラウド認証情報の窃取、バックドア設置 | 2026-03-30 | [GitHub Issue #24518](https://github.com/BerriAI/litellm/issues/24518) |
| axios | npm | 1.14.1, 0.30.4 | plain-crypto-js 経由の RAT ドロッパー | 2026-03-31 | （参照URL未記録） |
| keyv 等（Shai-Hulud系） | npm | keyv 6.0.0 他 計394パッケージ | preinstall 経由の Infostealer、ワーム性あり | 2026-08-07 | [GMO Flatt Security Blog](https://blog.flatt.tech/entry/keyv_compromise)（記事公開: 2026-08-04） |

> **注意**: 「調査基準日」は各脅威データを本リポジトリに反映した時点であり、参照URLに当時公開されていた情報のスナップショットです。参照元の追加調査・訂正・対象パッケージの拡大には自動追従しません。特にワーム型攻撃（keyv等）は参照元記事自身が「調査は継続中」と明言しており、本リストが実際に侵害された全パッケージを網羅していることは保証しません。最新状況は各参照URLで直接確認してください。

## 必要なもの

- [uv](https://docs.astral.sh/uv/) (Python パッケージマネージャ)
- [GitHub CLI (`gh`)](https://cli.github.com/) (GitHub スキャン時のみ)

外部 Python パッケージは不要。標準ライブラリのみで動作する。

### インストール

```bash
# uv
brew install uv        # Mac
curl -LsSf https://astral.sh/uv/install.sh | sh  # Linux

# gh (GitHub スキャン時のみ)
brew install gh && gh auth login  # Mac
```

## インストール

```bash
# グローバルにインストール
uv tool install /path/to/vuln-scanner

# GitHub から直接
uv tool install git+https://github.com/aRaikoFunakami/vuln-scanner.git
```

開発時: `uv sync && uv run vuln-scanner`

## 使い方

```bash
# ローカルディレクトリをスキャン（推移的依存も含め最も確実）
vuln-scanner --local ~/GitHub

# GitHub: 認証ユーザーの全リポジトリをスキャン
vuln-scanner

# 特定ユーザーのリポジトリ
vuln-scanner --user aRaikoFunakami

# Organization のリポジトリ
vuln-scanner --org access-company

# 特定リポジトリを直接指定
vuln-scanner --repos myorg/repo1,myorg/repo2

# GitHub + ローカル同時スキャン
vuln-scanner --org myorg --local ~/projects

# 出力先を指定（デフォルトは logs/ 配下に自動生成）
vuln-scanner --local ~/GitHub --output-dir ./my_results
```

## 終了コード

CI ゲートとして利用できます。

| コード | 意味 |
|-------|------|
| `0` | クリーン（VULNERABLE 検出なし） |
| `1` | VULNERABLE を検出 |
| `2` | 実行エラー（引数不正、gh 未認証など） |
| `3` | 予約（解析不可の依存ファイルあり — 今後実装） |

## 出力ファイル

| ファイル | 内容 |
|---------|------|
| `scan_report.md` | 調査レポート（概要・結果・調査方法） |
| `scan_results.csv` | 検出結果（管理シート貼付用） |
| `scan_results.json` | 検出結果（プログラム処理用） |
| `*.log` | タイムスタンプ付き調査ログ（エビデンス） |

## 検出範囲と制限事項

本ツールのスキャン方式ごとの検出能力は以下の通り:

| スキャン方式 | 直接依存 | lockfile 内の推移的依存 | lockfile なしの推移的依存 |
|------------|---------|----------------------|------------------------|
| **ローカルスキャン** | 検出可能 | 検出可能 | **実環境（pip freeze / node_modules）から検出可能** |
| **GitHub スキャン** | 検出可能 | 検出可能 | **検出不可**（`threats.json` の `indirect_packages` に登録されたもののみ） |

> **重要**: GitHub スキャンで lockfile（`poetry.lock`, `Pipfile.lock`, `package-lock.json`, `yarn.lock` 等）がないリポジトリでは、推移的依存（他のパッケージ経由で間接的にインストールされる脆弱パッケージ）を検出できません。より確実な調査が必要な場合は、対象リポジトリを `git clone` してローカルスキャン（`--local`）を実行してください。

## 判定基準

| 判定 | 意味 |
|------|------|
| VULNERABLE | 脆弱バージョンの使用、または悪意あるパッケージの検出 |
| SAFE | 対象パッケージを使用しているが安全なバージョン |
| WARNING | バージョン未指定で使用（脆弱バージョンの可能性） |
| CHECK_INDIRECT | 間接依存パッケージを検出（要手動確認） |

## 脅威の追加・更新方法

脅威定義は `src/vuln_scanner/threats/threats.json` で一元管理されている。

### 既存パッケージの脆弱バージョンを追加

`threats.json` のバージョン配列に追加するだけ:

```json
"direct_packages": {
  "axios": ["1.14.1", "0.30.4", "1.15.0"]
}
```

### 同じエコシステムの新しい脅威を追加

`threats.json` に新しいエントリを追加するだけ。コード変更不要:

```json
{
  "name": "lodash",
  "ecosystem": "npm",
  "direct_packages": {
    "lodash": ["4.99.0"]
  },
  "indirect_packages": [],
  "malicious_packages": [],
  "malicious_dirs": [],
  "malware_artifacts": {},
  "note_suffix": "",
  "report": {
    "background": ["#### lodash サプライチェーン攻撃 (npm)", "", "..."],
    "target_packages": ["#### npm エコシステム", "", "| 種別 | パッケージ名 | 理由 |", ...],
    "vulnerable_versions": ["#### lodash", "- `lodash@4.99.0`"],
    "malware_artifacts": [],
    "judgment_rows": ["| `lodash` のバージョンが `4.99.0` | **VULNERABLE** |"]
  }
}
```

### 新しいエコシステム（Go, Rust 等）を追加

1. `src/vuln_scanner/threats/ecosystems/go.py` を作成（パーサー、ファイルパターン、ローカルチェック）
2. `src/vuln_scanner/threats/__init__.py` の `_ECOSYSTEM_MODULES` に追加
3. `threats.json` にエントリ追加

## 安全性

GitHub スキャンは `gh` CLI 経由の GET リクエストのみで動作する。
コード内のバリデーション (`github_client.py`) により以下が強制される:

- 許可されたサブコマンド: `api`, `auth` のみ
- HTTP メソッド変更フラグ (`-X`, `--method`) の使用禁止
- API パスは `/user`, `/repos/`, `/search/` プレフィックスのみ許可

リポジトリへの書き込み・変更は一切行わない。

## ファイル構成

```
pyproject.toml
src/vuln_scanner/
  scanner.py                    -- エントリポイント・CLI
  github_client.py              -- GitHub API クライアント (gh CLI 経由)
  local_scanner.py              -- ローカルディレクトリスキャン (汎用)
  reporter.py                   -- CSV/JSON/Markdown/コンソール出力 (汎用)
  dependency_parser.py          -- 後方互換ラッパー
  threats/
    threats.json                -- 脅威定義データ (ここを編集して脅威を追加)
    base.py                     -- ThreatDefinition 抽象基底クラス
    data_driven.py              -- JSON → ThreatDefinition 変換
    __init__.py                 -- レジストリ・JSON 自動ロード
    ecosystems/
      python.py                 -- Python パーサー・pip/venv チェック
      npm.py                    -- npm パーサー・node_modules チェック
```

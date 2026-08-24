"""Data-driven threat definition backed by JSON + ecosystem module.

This class implements :class:`ThreatDefinition` generically so that new
threats can be added by editing ``threats.json`` and (optionally) adding
an ecosystem module, rather than writing a new Python class.
"""

from __future__ import annotations

import re
from types import ModuleType
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from vuln_scanner.threats.base import (
    CHECK_INDIRECT,
    SAFE,
    VULNERABLE,
    WARNING,
    ThreatDefinition,
    canonical_version,
    is_exact_version,
    most_severe,
    range_may_include,
)


class DataDrivenThreat(ThreatDefinition):
    """A :class:`ThreatDefinition` driven entirely by a JSON data dict
    and a pluggable ecosystem module.

    Parameters
    ----------
    data:
        One element of the ``threats.json`` array.
    ecosystem_module:
        The ecosystem helper module (e.g. ``ecosystems.python`` or
        ``ecosystems.npm``).
    """

    def __init__(self, data: dict, ecosystem_module: ModuleType) -> None:
        self._data = data
        self._eco = ecosystem_module

        # Pre-compute package sets
        self._vulnerable_versions: Set[str] = set()
        self._versions_by_package: Dict[str, Set[str]] = {}
        # Canonicalized vulnerable versions per package: an exact pin like
        # "1.14.1+cpu" / "v1.14.1" / "01.14.01" is the same release as the
        # stored "1.14.1" and must not slip to SAFE on a raw string test.
        self._canon_versions_by_package: Dict[str, Set[str]] = {}
        for pkg_name, versions in data["direct_packages"].items():
            self._vulnerable_versions.update(versions)
            normalized = pkg_name.lower().replace("-", "_")
            self._versions_by_package.setdefault(normalized, set()).update(versions)
            self._canon_versions_by_package.setdefault(normalized, set()).update(
                canonical_version(v) for v in versions
            )

        self._direct_packages_set: Set[str] = set(data["direct_packages"].keys())
        self._indirect: Set[str] = set(data.get("indirect_packages", []))
        self._malicious: Set[str] = set(data.get("malicious_packages", []))
        self._note_suffix: str = data.get("note_suffix", "")

        # Normalized lookups, precomputed once -- judge() runs per finding
        def _norm(names: Set[str]) -> Set[str]:
            return {n.lower().replace("-", "_") for n in names}

        self._direct_normalized = _norm(self._direct_packages_set)
        self._indirect_normalized = _norm(self._indirect)
        self._malicious_display = {
            m.lower().replace("-", "_"): m for m in self._malicious
        }

    # ── Properties ───────────────────────────────────────────────────────

    @property
    def name(self) -> str:
        return self._data["name"]

    @property
    def ecosystem(self) -> str:
        return self._data["ecosystem"]

    @property
    def vulnerable_versions(self) -> Set[str]:
        return set(self._vulnerable_versions)

    @property
    def direct_package(self) -> str:
        # Return the first (usually only) direct package
        return next(iter(self._direct_packages_set))

    @property
    def direct_packages(self) -> Set[str]:
        return set(self._direct_packages_set)

    @property
    def related_packages(self) -> Set[str]:
        return self._indirect | self._malicious

    # `all_packages` is inherited from the base class, which already composes
    # it from `direct_packages | related_packages`.

    # ── Parsing ──────────────────────────────────────────────────────────

    def get_parsers(
        self,
    ) -> Dict[str, Callable[..., List[Tuple[str, Optional[str]]]]]:
        return self._eco.get_parsers(self.all_packages)

    def get_file_patterns_glob(self) -> List[str]:
        return list(self._eco.FILE_PATTERNS_GLOB)

    def get_file_patterns_regex(self) -> List[re.Pattern[str]]:
        return list(self._eco.FILE_PATTERNS_REGEX)

    def match_file(
        self, basename: str
    ) -> Optional[Callable[..., List[Tuple[str, Optional[str]]]]]:
        return self._eco.match_file(basename, self.get_parsers())

    # ── Judgment ──────────────────────────────────────────────────────────

    def judge(
        self, package_name: str, version: Optional[str]
    ) -> Tuple[str, str]:
        normalized = package_name.lower().replace("-", "_")

        # Malicious packages -- presence alone is VULNERABLE
        if normalized in self._malicious_display:
            original_name = self._malicious_display[normalized]
            return (
                VULNERABLE,
                f"悪意あるパッケージ {original_name} を検出{self._note_suffix}",
            )

        # Indirect packages -- need further checking
        if normalized in self._indirect_normalized:
            # Find which direct package they depend on
            direct_name = next(iter(self._direct_packages_set))
            return (
                CHECK_INDIRECT,
                f"{direct_name}を間接依存として利用するパッケージ",
            )

        # Direct packages
        if normalized in self._direct_normalized:
            vulnerable = self._versions_by_package.get(normalized, set())
            canon_vulnerable = self._canon_versions_by_package.get(normalized, set())
            if version:
                # "==1.2.3" (PEP 508) pins exactly like "1.2.3".
                version = version.strip()
                if version.startswith("=="):
                    version = version[2:].strip()
                # Compare exact pins in canonical form: "1.14.1+cpu",
                # "v1.14.1", "1!1.14.1", "01.14.01" are all the same
                # release as the stored "1.14.1" and must not slip to
                # SAFE on a raw string test (issues #9/#25/#26).
                if is_exact_version(version):
                    if canonical_version(version) in canon_vulnerable:
                        return (
                            VULNERABLE,
                            f"脆弱バージョン {version} を使用{self._note_suffix}",
                        )
                    return SAFE, f"バージョン {version} は安全"
                # Not an exact pin -- still catch a raw string match (e.g.
                # a stored prerelease) before treating it as a range.
                if version in vulnerable:
                    return (
                        VULNERABLE,
                        f"脆弱バージョン {version} を使用{self._note_suffix}",
                    )
                # Range specifier (^1.14.0, >=1.0, ~=1.82, ...): never
                # assert SAFE for a range that can resolve to a
                # vulnerable version (CLAUDE.md レビュー観点4)
                if range_may_include(version, vulnerable):
                    return (
                        WARNING,
                        f"バージョン指定 {version} は脆弱バージョンを除外できない"
                        "（実際に解決されたバージョンの確認が必要）",
                    )
                return (
                    SAFE,
                    f"範囲指定 {version} は既知の脆弱バージョンを含まない",
                )
            return (
                WARNING,
                "バージョン未指定（脆弱バージョンがインストールされた可能性あり）",
            )

        return SAFE, "対象外パッケージ"

    # ── Local-scanning hooks ─────────────────────────────────────────────

    def check_installed(
        self,
        root_dir: str,
        dep_files: List[str],
        logger: Any = None,
    ) -> List[Dict[str, Any]]:
        eco = self._eco
        # Python ecosystem: check_installed(root_dir, target_packages, logger)
        # npm ecosystem: check_installed(root_dir, target_packages, dep_files, logger)
        if self.ecosystem == "python":
            return eco.check_installed(root_dir, self.all_packages, logger)
        elif self.ecosystem == "npm":
            return eco.check_installed(root_dir, self.all_packages, dep_files, logger)
        return []

    def find_malicious_dirs(
        self,
        root_dir: str,
        logger: Any = None,
    ) -> List[str]:
        malicious_dirs = self._data.get("malicious_dirs", [])
        if not malicious_dirs:
            return []
        if hasattr(self._eco, "find_malicious_dirs"):
            return self._eco.find_malicious_dirs(root_dir, malicious_dirs, logger)
        return []

    def check_artifacts(self, logger: Any = None) -> List[Dict[str, Any]]:
        artifact_paths = self._data.get("malware_artifacts", {})
        if not artifact_paths:
            return []
        if hasattr(self._eco, "check_artifacts"):
            return self._eco.check_artifacts(artifact_paths, logger)
        return []

    def enrich_findings(
        self,
        findings: List[Dict[str, Any]],
        installed_info: List[Dict[str, Any]],
        dep_files: List[str],
        root_dir: str,
        logger: Any = None,
    ) -> None:
        if not hasattr(self._eco, "enrich_findings"):
            return
        # Judge across ALL registered threats of this ecosystem, not just
        # this one: a single threat's judge returns SAFE for out-of-scope
        # packages and would overwrite other threats' verdicts (issue #5).
        # self.judge is merged in so a threat that was never register()ed
        # (tests, programmatic use) still judges its own packages.
        # Deferred import: threats/__init__ imports this module.
        from vuln_scanner.threats import judge as registry_judge

        def judge_fn(pkg: str, ver: Optional[str]) -> Tuple[str, str]:
            return most_severe(
                registry_judge(pkg, ver, ecosystem=self.ecosystem),
                self.judge(pkg, ver),
            )

        self._eco.enrich_findings(
            findings, installed_info, dep_files, root_dir, judge_fn, logger,
        )

    # ── Report text ──────────────────────────────────────────────────────

    def report_background(self) -> List[str]:
        return list(self._data["report"]["background"])

    def report_target_packages(self) -> List[str]:
        return list(self._data["report"]["target_packages"])

    def report_vulnerable_versions(self) -> List[str]:
        return list(self._data["report"]["vulnerable_versions"])

    def report_malware_artifacts(self) -> List[str]:
        return list(self._data["report"].get("malware_artifacts", []))

    def report_judgment_rows(self) -> List[str]:
        return list(self._data["report"]["judgment_rows"])

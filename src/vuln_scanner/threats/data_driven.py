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
        for pkg_name, versions in data["direct_packages"].items():
            self._vulnerable_versions.update(versions)
            normalized = pkg_name.lower().replace("-", "_")
            self._versions_by_package.setdefault(normalized, set()).update(versions)

        self._direct_packages_set: Set[str] = set(data["direct_packages"].keys())
        self._indirect: Set[str] = set(data.get("indirect_packages", []))
        self._malicious: Set[str] = set(data.get("malicious_packages", []))
        self._note_suffix: str = data.get("note_suffix", "")

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
        if normalized in {m.lower().replace("-", "_") for m in self._malicious}:
            original_name = package_name
            # Find the original (non-normalized) name for display
            for m_name in self._malicious:
                if m_name.lower().replace("-", "_") == normalized:
                    original_name = m_name
                    break
            return (
                VULNERABLE,
                f"悪意あるパッケージ {original_name} を検出{self._note_suffix}",
            )

        # Indirect packages -- need further checking
        if normalized in {i.lower().replace("-", "_") for i in self._indirect}:
            # Find which direct package they depend on
            direct_name = next(iter(self._direct_packages_set))
            return (
                CHECK_INDIRECT,
                f"{direct_name}を間接依存として利用するパッケージ",
            )

        # Direct packages
        if normalized in {d.lower().replace("-", "_") for d in self._direct_packages_set}:
            if version and version in self._versions_by_package.get(normalized, set()):
                suffix = self._note_suffix
                return (
                    VULNERABLE,
                    f"脆弱バージョン {version} を使用{suffix}",
                )
            if version:
                return SAFE, f"バージョン {version} は安全"
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
        if hasattr(self._eco, "enrich_findings"):
            # Judge across ALL registered threats, not just this one:
            # self.judge returns SAFE for packages outside this threat's
            # scope, so passing it here lets the last-enriched threat
            # overwrite other threats' VULNERABLE verdicts (issue #5).
            from vuln_scanner.threats import judge as cross_threat_judge

            self._eco.enrich_findings(
                findings, installed_info, dep_files, root_dir,
                cross_threat_judge, logger,
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

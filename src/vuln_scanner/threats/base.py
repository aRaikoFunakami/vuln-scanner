"""Abstract base class for supply-chain threat definitions.

This module defines the interface that every threat plugin must implement,
along with the canonical verdict constants shared across the scanner.

Compatible with Python 3.9+.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# ── Verdict constants (canonical location) ──────────────────────────────────
VULNERABLE = "VULNERABLE"
SAFE = "SAFE"
WARNING = "WARNING"
CHECK_INDIRECT = "CHECK_INDIRECT"


class ThreatDefinition(ABC):
    """Base class for a supply-chain threat definition.

    Sub-classes describe *one* threat (e.g. a compromised PyPI package) and
    provide parsers, judgment logic, local-scanning hooks, and report text.
    """

    # ── Abstract properties ──────────────────────────────────────────────

    @property
    @abstractmethod
    def name(self) -> str:
        """Short human-readable identifier (e.g. ``"litellm"``)."""
        ...

    @property
    @abstractmethod
    def ecosystem(self) -> str:
        """Package ecosystem (e.g. ``"python"``, ``"npm"``)."""
        ...

    @property
    @abstractmethod
    def vulnerable_versions(self) -> Set[str]:
        """Set of version strings known to be compromised."""
        ...

    @property
    @abstractmethod
    def direct_package(self) -> str:
        """Primary package name targeted by the attack."""
        ...

    @property
    @abstractmethod
    def related_packages(self) -> Set[str]:
        """Indirect dependencies, malicious shims, etc."""
        ...

    # ── Computed properties ─────────────────────────────────────────────

    @property
    def direct_packages(self) -> Set[str]:
        """All directly-targeted package names.

        Defaults to ``{direct_package}``; override when an attack targets
        more than one package directly (e.g. a mass worm compromising
        hundreds of packages at once).
        """
        return {self.direct_package}

    @property
    def all_packages(self) -> Set[str]:
        """Union of *direct_packages* and *related_packages*."""
        return self.direct_packages | self.related_packages

    # ── Abstract methods – parsing ───────────────────────────────────────

    @abstractmethod
    def get_parsers(self) -> Dict[str, Callable[..., List[Tuple[str, Optional[str]]]]]:
        """Return a mapping of parser-key to parser callable.

        Each parser callable accepts ``(content: str)`` and returns a list of
        ``(package_name, version_or_None)`` tuples.
        """
        ...

    @abstractmethod
    def get_file_patterns_glob(self) -> List[str]:
        """Glob patterns used for local filesystem scanning."""
        ...

    @abstractmethod
    def get_file_patterns_regex(self) -> List[re.Pattern[str]]:
        """Compiled regex patterns for matching file paths in GitHub trees."""
        ...

    @abstractmethod
    def match_file(self, basename: str) -> Optional[Callable[..., List[Tuple[str, Optional[str]]]]]:
        """Return the parser for *basename*, or ``None`` if not recognized."""
        ...

    # ── Abstract method – judgment ───────────────────────────────────────

    @abstractmethod
    def judge(self, package_name: str, version: Optional[str]) -> Tuple[str, str]:
        """Classify a single finding.

        Returns:
            ``(verdict, note)`` where *verdict* is one of the module-level
            verdict constants and *note* is a human-readable explanation.
        """
        ...

    # ── Local-scanning hooks (default implementations) ───────────────────

    def check_installed(
        self,
        root_dir: str,
        dep_files: List[str],
        logger: Any = None,
    ) -> List[Dict[str, Any]]:
        """Detect packages installed in the runtime environment.

        Returns a list of dicts, each with at least::

            {"environment": str, "ecosystem": str, "python": str,
             "packages": {name: version}}

        The default implementation returns an empty list.
        """
        return []

    def check_artifacts(self, logger: Any = None) -> List[Dict[str, Any]]:
        """Check for known malware artifacts on disk.

        Returns a list of dicts describing found artifacts.
        The default implementation returns an empty list.
        """
        return []

    def find_malicious_dirs(
        self,
        root_dir: str,
        logger: Any = None,
    ) -> List[str]:
        """Search for directories belonging to malicious packages.

        Returns a list of absolute paths.
        The default implementation returns an empty list.
        """
        return []

    def enrich_findings(
        self,
        findings: List[Dict[str, Any]],
        installed_info: List[Dict[str, Any]],
        dep_files: List[str],
        root_dir: str,
        logger: Any = None,
    ) -> None:
        """Post-process *findings* in place (e.g. fill in missing versions).

        The default implementation is a no-op.
        """

    # ── Abstract methods – report text ───────────────────────────────────

    @abstractmethod
    def report_background(self) -> List[str]:
        """Markdown lines describing the attack background."""
        ...

    @abstractmethod
    def report_target_packages(self) -> List[str]:
        """Markdown lines listing target packages (with table/heading)."""
        ...

    @abstractmethod
    def report_vulnerable_versions(self) -> List[str]:
        """Markdown lines listing vulnerable versions (with heading)."""
        ...

    @abstractmethod
    def report_judgment_rows(self) -> List[str]:
        """Markdown table rows for the judgment-logic section."""
        ...

    # ── Report text – optional override ──────────────────────────────────

    def report_malware_artifacts(self) -> List[str]:
        """Markdown lines describing malware artifacts to check.

        The default implementation returns an empty list.
        """
        return []

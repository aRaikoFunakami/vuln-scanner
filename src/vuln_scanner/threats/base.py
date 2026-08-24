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
# A recognized dependency file that could not be analyzed: no parser
# understands its format (e.g. a future lockfile generation), or it
# failed to parse as its expected format (e.g. corrupted JSON). Distinct
# from SAFE/a clean scan -- "not analyzed" must never look like "clean"
# (CLAUDE.md レビュー観点2, issue #11).
NOT_ANALYZED = "NOT_ANALYZED"

# Severity order for combining verdicts from multiple threats: a package
# listed by two threats must get the worst applicable verdict, never be
# masked by whichever threat happened to answer first.
_VERDICT_SEVERITY = {SAFE: 0, CHECK_INDIRECT: 1, WARNING: 2, VULNERABLE: 3}


def most_severe(*results: Tuple[str, str]) -> Tuple[str, str]:
    """Return the ``(verdict, note)`` with the highest severity.

    Ties keep the earliest argument, so callers can put the preferred
    source first.
    """
    return max(results, key=lambda r: _VERDICT_SEVERITY.get(r[0], 0))


# ── Version-spec helpers ────────────────────────────────────────────────────

_EXACT_VERSION_RE = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?$")

_RANGE_RE = re.compile(
    r"^(\^|~=|~|>=|>|<=|<|==|=)?\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?"
    r"(?:[-+][0-9A-Za-z.+-]*)?$"
)


def is_exact_version(spec: str) -> bool:
    """True if *spec* pins one concrete version (``1.2.3``, ``1.2.3-rc.1``)."""
    return bool(_EXACT_VERSION_RE.match(spec.strip()))


def canonical_version(v: str) -> str:
    """Canonical form for exact-version equality against threats.json.

    ``is_exact_version`` accepts forms that are the SAME release as a
    stored bare version but not string-equal, so a raw membership test
    let them slip to SAFE. Normalize them all to the stored shape:

    - drop a leading ``v`` (``v1.14.1``)
    - drop PEP 440 local/build metadata (``1.14.1+cpu`` -> ``1.14.1``)
    - drop a PEP 440 epoch (``1!1.14.1`` -> ``1.14.1``; conservative --
      the safe direction for a scanner is to still match)
    - strip leading zeros from numeric release segments
      (``01.14.01`` -> ``1.14.1``)

    Prerelease (``-rc.1``) is part of a version's identity and kept.
    """
    v = v.strip()
    if v[:1] in ("v", "V"):
        v = v[1:]
    v = v.split("+", 1)[0]           # local / build metadata
    if "!" in v:                     # epoch
        v = v.split("!", 1)[1]
    rel, sep, pre = v.partition("-")
    norm = [str(int(p)) if p.isdigit() else p for p in rel.split(".")]
    return ".".join(norm) + (sep + pre if sep else "")


def _ver_tuple(v: str) -> Optional[Tuple[int, int, int]]:
    m = re.match(r"v?(\d+)\.(\d+)(?:\.(\d+))?", v.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def range_may_include(spec: str, versions: Set[str]) -> bool:
    """Can version range *spec* resolve to any version in *versions*?

    Supports the common single-operator forms: npm ``^`` ``~``,
    ``>=`` ``>`` ``<=`` ``<``, PEP 440 ``~=``, and bare/partial pins.
    Anything unrecognized or compound (``||``, hyphen ranges, ``*``)
    is conservatively treated as "may include" -- a range must never be
    declared safe on a guess.  Prerelease tags are ignored for the
    comparison (also conservative).
    """
    spec = spec.strip()
    vulns = [t for t in (_ver_tuple(v) for v in versions) if t is not None]
    if not vulns:
        return False
    m = _RANGE_RE.match(spec)
    if not m:
        return True  # "*", "1.x", "|| ", "1.0 - 2.0", "latest", ...
    op = m.group(1) or ""
    major = int(m.group(2))
    minor = int(m.group(3)) if m.group(3) is not None else None
    patch = int(m.group(4)) if m.group(4) is not None else None
    base = (major, minor or 0, patch or 0)

    def hit(v: Tuple[int, int, int]) -> bool:
        if op == ">=":
            return v >= base
        if op == ">":
            return v > base
        if op == "<=":
            return v <= base
        if op == "<":
            return v < base
        if op == "^":
            if major > 0:
                return v[0] == major and v >= base
            if (minor or 0) > 0:
                return v[0] == 0 and v[1] == minor and v >= base
            return v == base
        if op == "~":
            if minor is None:
                return v[0] == major
            return v[0] == major and v[1] == minor and v >= base
        if op == "~=":
            if patch is None:
                return v[0] == major and v >= base
            return v[0] == major and v[1] == minor and v >= base
        # "=="/"="/bare partial pin ("1.2"): prefix semantics
        if minor is None:
            return v[0] == major
        if patch is None:
            return v[0] == major and v[1] == minor
        return v == base

    return any(hit(v) for v in vulns)


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

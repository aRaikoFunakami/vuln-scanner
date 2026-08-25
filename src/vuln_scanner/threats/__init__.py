"""Threat registry and aggregate dispatch functions.

Threats are loaded from ``threats.json`` and instantiated as
``DataDrivenThreat`` objects backed by ecosystem-specific modules.
"""

from __future__ import annotations

import json
import os
from typing import Callable, Dict, List, Optional, Set, Tuple

from vuln_scanner.threats.base import (  # noqa: F401 – re-export
    VULNERABLE,
    SAFE,
    WARNING,
    CHECK_INDIRECT,
    NOT_ANALYZED,
    ThreatDefinition,
    most_severe,
)

# ── Registry ────────────────────────────────────────────────────────────────

_THREATS: List[ThreatDefinition] = []

# Normalized package names owned by each threat, precomputed at register()
# time: judge() runs once per finding and must not rebuild a 400-element
# set per call.
_OWNED_NORMALIZED: Dict[int, Set[str]] = {}


def register(threat: ThreatDefinition) -> None:
    """Register a threat definition."""
    _THREATS.append(threat)
    _OWNED_NORMALIZED[id(threat)] = {
        p.lower().replace("-", "_") for p in threat.all_packages
    }


def get_all_threats() -> List[ThreatDefinition]:
    """Return all registered threat definitions."""
    return list(_THREATS)


# ── Aggregate helpers ───────────────────────────────────────────────────────

def get_all_packages() -> Set[str]:
    """Return the union of ``all_packages`` across every registered threat."""
    result: Set[str] = set()
    for t in _THREATS:
        result |= t.all_packages
    return result


def get_all_file_patterns_regex():
    """Aggregate compiled regex patterns from all threats (for GitHub client)."""
    patterns = []
    for t in _THREATS:
        patterns.extend(t.get_file_patterns_regex())
    return patterns


def get_all_file_patterns_glob() -> List[str]:
    """Aggregate glob patterns from all threats (for local scanner)."""
    seen: Set[str] = set()
    unique: List[str] = []
    for t in _THREATS:
        for p in t.get_file_patterns_glob():
            if p not in seen:
                seen.add(p)
                unique.append(p)
    return unique


# ── Aggregate dispatch ──────────────────────────────────────────────────────

def get_parser(file_path: str) -> Optional[Callable]:
    """Return a parser for *file_path* by consulting every registered threat.

    If multiple threats can parse the same file, a composite parser that
    merges results from all matching parsers is returned.

    The returned callable carries a ``.ecosystem`` attribute (the ecosystem
    string, or ``None`` if -- hypothetically -- matching threats span more
    than one ecosystem) so callers can pass it through to :func:`judge`
    (issue #16). File-pattern globs never overlap across ecosystems today,
    so in practice this is always a single ecosystem.
    """
    basename = file_path.rsplit("/", 1)[-1] if "/" in file_path else file_path
    parsers = []
    ecosystems: set = set()
    for t in _THREATS:
        p = t.match_file(basename)
        if p is not None:
            parsers.append(p)
            ecosystems.add(t.ecosystem)
    if not parsers:
        return None
    ecosystem = next(iter(ecosystems)) if len(ecosystems) == 1 else None
    if len(parsers) == 1:
        parsers[0].ecosystem = ecosystem  # type: ignore[attr-defined]
        return parsers[0]

    # Composite parser – merge results, deduplicate
    def _composite(content: str) -> List[Tuple[str, Optional[str]]]:
        results: List[Tuple[str, Optional[str]]] = []
        seen: set = set()
        for parser_fn in parsers:
            for item in parser_fn(content):
                if item not in seen:
                    seen.add(item)
                    results.append(item)
        return results

    _composite.ecosystem = ecosystem  # type: ignore[attr-defined]
    return _composite


def judge(
    package_name: str,
    version: Optional[str],
    ecosystem: Optional[str] = None,
) -> Tuple[str, str]:
    """Judge *package_name* across every registered threat that owns it.

    Consults ALL owning threats and returns the most severe verdict, so a
    package listed by two threats is never masked by whichever registered
    first.  Pass *ecosystem* to restrict to threats of that ecosystem --
    npm and PyPI package names collide, and a version that is malicious on
    one registry says nothing about the other.
    """
    normalized = package_name.lower().replace("-", "_")
    best: Optional[Tuple[str, str]] = None
    for t in _THREATS:
        if ecosystem is not None and t.ecosystem != ecosystem:
            continue
        if normalized in _OWNED_NORMALIZED[id(t)]:
            result = t.judge(package_name, version)
            best = result if best is None else most_severe(best, result)
    return best if best is not None else (SAFE, "対象外パッケージ")


# ── Auto-load threats from JSON ─────────────────────────────────────────────

from vuln_scanner.threats.data_driven import DataDrivenThreat  # noqa: E402
from vuln_scanner.threats.ecosystems import python as _py_eco  # noqa: E402
from vuln_scanner.threats.ecosystems import npm as _npm_eco  # noqa: E402

_ECOSYSTEM_MODULES = {
    "python": _py_eco,
    "npm": _npm_eco,
}

def _validate_entry(entry, index: int) -> None:
    """Fail fast with a message naming the offending entry if a threat is
    missing a field detection requires (issue #30).

    Only fields that break parsing/judgment are enforced here. Report
    prose (``report.*``) is optional and degrades to empty sections --
    see ``DataDrivenThreat._report`` -- so it is intentionally not
    required, to avoid refusing to load over a cosmetic omission.
    """
    where = f"threats.json entry #{index}"
    if not isinstance(entry, dict):
        raise ValueError(f"{where}: must be a JSON object, got {type(entry).__name__}")
    name = entry.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError(f"{where}: missing or empty required field 'name'")
    where = f"threats.json threat {name!r}"
    eco = entry.get("ecosystem")
    if eco not in _ECOSYSTEM_MODULES:
        raise ValueError(
            f"{where}: unknown or missing 'ecosystem' {eco!r}. "
            f"Available: {list(_ECOSYSTEM_MODULES)}"
        )
    direct = entry.get("direct_packages")
    if not isinstance(direct, dict) or not direct:
        raise ValueError(
            f"{where}: 'direct_packages' must be a non-empty object "
            "(malicious-only threats are not currently supported)"
        )
    for pkg, versions in direct.items():
        if not isinstance(versions, list):
            raise ValueError(
                f"{where}: direct_packages[{pkg!r}] must be a list of "
                f"version strings, got {type(versions).__name__}"
            )
        # Elements must be strings: a bare JSON number (1.14 instead of
        # "1.14") or null would otherwise pass here and crash
        # canonical_version() with an un-named AttributeError at import.
        for v in versions:
            if not isinstance(v, str):
                raise ValueError(
                    f"{where}: direct_packages[{pkg!r}] contains a non-string "
                    f"version {v!r} ({type(v).__name__}); quote it in threats.json"
                )


# Test-only seam: lets the test suite load a throwaway threat DB (dummy
# package identifiers that don't collide with anything real) instead of
# the production one, so it can exercise full detection without ever
# committing genuinely-vulnerable-looking package/version strings to the
# repo. Production runs never set this.
_DB_PATH = os.environ.get("VULN_SCANNER_THREATS_JSON") or os.path.join(
    os.path.dirname(__file__), "threats.json"
)
with open(_DB_PATH, encoding="utf-8") as _f:
    _DB = json.load(_f)

for _index, _entry in enumerate(_DB):
    _validate_entry(_entry, _index)
    register(DataDrivenThreat(_entry, _ECOSYSTEM_MODULES[_entry["ecosystem"]]))

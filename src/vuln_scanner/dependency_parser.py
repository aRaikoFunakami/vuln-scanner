"""Backward-compatible facade for supply-chain threat detection.

All logic now lives in the ``threats/`` subpackage.  This module re-exports
the public API so that existing callers continue to work unchanged.
"""

# ── Verdict constants ───────────────────────────────────────────────────────
from vuln_scanner.threats.base import (  # noqa: F401
    VULNERABLE,
    SAFE,
    WARNING,
    CHECK_INDIRECT,
)

# ── Aggregate dispatch ──────────────────────────────────────────────────────
from vuln_scanner.threats import (  # noqa: F401
    judge,
    get_parser,
    get_all_threats as _get_all_threats,
)

# ── Parser functions (backward compat) ──────────────────────────────────────
from vuln_scanner.threats.ecosystems.python import (  # noqa: F401
    parse_requirements_txt,
    parse_pyproject_toml,
    parse_pipfile,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_setup_py,
    parse_setup_cfg,
    parse_dockerfile,
)
from vuln_scanner.threats.ecosystems.npm import (  # noqa: F401
    parse_package_json,
    parse_package_lock_json,
    parse_yarn_lock,
    parse_pnpm_lock,
)

# ── Threat-specific constants (backward compat) ────────────────────────────
# Computed from the first registered threat of each ecosystem.
_threats = _get_all_threats()
_litellm = next((t for t in _threats if t.name == "litellm"), None)
_axios = next((t for t in _threats if t.name == "axios"), None)

if _litellm:
    LITELLM_VULNERABLE_VERSIONS = _litellm.vulnerable_versions
    LITELLM_DIRECT_PACKAGE = _litellm.direct_package
    LITELLM_INDIRECT_PACKAGES = _litellm.related_packages
    LITELLM_ALL_PACKAGES = _litellm.all_packages
    VULNERABLE_VERSIONS = LITELLM_VULNERABLE_VERSIONS
    DIRECT_PACKAGE = LITELLM_DIRECT_PACKAGE
    INDIRECT_PACKAGES = LITELLM_INDIRECT_PACKAGES
    ALL_PACKAGES = LITELLM_ALL_PACKAGES

if _axios:
    AXIOS_VULNERABLE_VERSIONS = _axios.vulnerable_versions
    AXIOS_DIRECT_PACKAGE = _axios.direct_package
    AXIOS_MALICIOUS_PACKAGES = _axios.related_packages
    AXIOS_ALL_PACKAGES = _axios.all_packages

# ── PARSERS dict (backward compat) ─────────────────────────────────────────
# Tag each parser with its ecosystem, same as threats.get_parser() (issue
# #16 follow-up) -- a caller reading PARSERS[...] directly must be able to
# pass ecosystem=parser.ecosystem to judge() too, or it silently loses the
# npm/PyPI collision filter this facade's callers can't see is expected.
PARSERS = {}
for _t in _threats:
    for _key, _parser in _t.get_parsers().items():
        _parser.ecosystem = _t.ecosystem  # type: ignore[attr-defined]
        PARSERS[_key] = _parser

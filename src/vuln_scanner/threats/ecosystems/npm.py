"""npm ecosystem parsers and local-scanning helpers.

All functions are package-name independent -- ``target_packages`` is always
passed in as a parameter rather than referencing module-level constants.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from vuln_scanner.threats.base import most_severe

# ── File-matching patterns ───────────────────────────────────────────────────

FILE_PATTERNS_GLOB: List[str] = [
    "**/package.json",
    "**/package-lock.json",
    "**/yarn.lock",
    "**/pnpm-lock.yaml",
]

FILE_PATTERNS_REGEX: List[re.Pattern[str]] = [
    re.compile(r"(^|/)package\.json$"),
    re.compile(r"(^|/)package-lock\.json$"),
    re.compile(r"(^|/)yarn\.lock$"),
    re.compile(r"(^|/)pnpm-lock\.yaml$"),
]

# ── Parser helpers ───────────────────────────────────────────────────────────


def _extract_semver(version_str: Optional[str]) -> Optional[str]:
    """Extract the semver portion from an npm version specifier.

    Examples::

        "^1.14.0" -> "1.14.0"
        "~0.30.4" -> "0.30.4"
        "1.14.1"  -> "1.14.1"
    """
    if not version_str:
        return None
    m = re.search(r"(\d+\.\d+\.\d+)", version_str)
    return m.group(1) if m else None


def parse_package_json(
    content: str,
    target_packages: Set[str],
) -> List[Tuple[str, Optional[str]]]:
    """Parse ``package.json`` for target npm packages.

    Inspects ``dependencies``, ``devDependencies``, ``optionalDependencies``,
    and ``peerDependencies`` sections.

    Returns list of ``(package_name, version_or_None)`` tuples.
    """
    results: List[Tuple[str, Optional[str]]] = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return results
    for section in (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for pkg_name, ver_spec in deps.items():
            if pkg_name.lower() in target_packages:
                ver = _extract_semver(ver_spec) if isinstance(ver_spec, str) else None
                results.append((pkg_name.lower(), ver))
    return results


def parse_package_lock_json(
    content: str,
    target_packages: Set[str],
) -> List[Tuple[str, Optional[str]]]:
    """Parse ``package-lock.json`` (v1, v2, and v3 formats).

    Returns deduplicated list of ``(package_name, version_or_None)`` tuples.
    """
    results: List[Tuple[str, Optional[str]]] = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return results

    # v2/v3 format: "packages" key with "node_modules/..." keys
    # (e.g. "node_modules/keyv" or the scoped "node_modules/@scope/pkg" --
    # split on the last "node_modules/" segment so scoped names keep their
    # "@scope/" prefix instead of only the last path component)
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, info in packages.items():
            pkg_name = key.rsplit("node_modules/", 1)[-1] if "node_modules/" in key else key
            if pkg_name.lower() in target_packages:
                ver = info.get("version")
                results.append((pkg_name.lower(), ver))

    # v1 format: "dependencies" key
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        for pkg_name, info in deps.items():
            if pkg_name.lower() in target_packages:
                ver = info.get("version") if isinstance(info, dict) else None
                results.append((pkg_name.lower(), ver))
            # Check nested (transitive) dependencies
            if isinstance(info, dict) and "dependencies" in info:
                for sub_name, sub_info in info["dependencies"].items():
                    if sub_name.lower() in target_packages:
                        sub_ver = (
                            sub_info.get("version")
                            if isinstance(sub_info, dict)
                            else None
                        )
                        results.append((sub_name.lower(), sub_ver))

    # Deduplicate while preserving order
    seen: set[Tuple[str, Optional[str]]] = set()
    unique: List[Tuple[str, Optional[str]]] = []
    for pair in results:
        if pair not in seen:
            seen.add(pair)
            unique.append(pair)
    return unique


def parse_yarn_lock(
    content: str,
    target_packages: Set[str],
) -> List[Tuple[str, Optional[str]]]:
    """Parse ``yarn.lock`` for target npm packages.

    Recognises header lines such as ``axios@^1.14.0:`` (classic) and
    ``"axios@npm:1.14.1":`` (berry v2+), and the subsequent version line
    in either format: ``version "1.14.1"`` (classic) or
    ``version: 1.14.1`` (berry).

    Returns deduplicated list of ``(package_name, version_or_None)``
    tuples (berry can list one package under both ``npm:`` and
    ``virtual:`` headers with the same version).
    """
    # ponytail: berry alias (`myalias@npm:keyv@6.0.0`) and `patch:`
    # protocol headers yield names like "myalias@npm:keyv" and are
    # skipped -- parse the `resolution:` field if alias coverage is
    # ever needed.  (patch: entries keep their base `npm:` entry, so
    # only aliased installs are actually missed.)
    results: List[Tuple[str, Optional[str]]] = []
    seen: set = set()
    current_pkg: Optional[str] = None
    for line in content.splitlines():
        # Header line: "axios@^1.14.0:" or "axios@^1.14.0, axios@^1.0.0:"
        if not line.startswith(" ") and line.endswith(":"):
            header = line.rstrip(":")
            parts = [p.strip().strip('"') for p in header.split(",")]
            pkg_name: Optional[str] = None
            for part in parts:
                # rfind: the last "@" separates name from range/version,
                # so scoped names ("@scope/pkg@^1.0.0") keep their scope
                at_idx = part.rfind("@")
                name = part[:at_idx] if at_idx > 0 else part
                if name.lower() in target_packages:
                    pkg_name = name.lower()
                    break
            current_pkg = pkg_name
        elif current_pkg and line.strip().startswith("version"):
            m = re.match(r'\s+version:?\s+"?([^"\s]+)"?', line)
            # "0.0.0-use.local" is berry's placeholder for workspace:/
            # portal:/link: entries, not an installed version -- emitting
            # it would judge the package SAFE with a fabricated version
            if m and m.group(1) != "0.0.0-use.local":
                pair = (current_pkg, m.group(1))
                if pair not in seen:
                    seen.add(pair)
                    results.append(pair)
            current_pkg = None
    return results


def parse_pnpm_lock(
    content: str,
    target_packages: Set[str],
) -> List[Tuple[str, Optional[str]]]:
    """Parse ``pnpm-lock.yaml`` for target npm packages.

    Reads package keys from the top-level ``packages:`` section only:
    ``snapshots:`` (v9) repeats every package, and ``overrides:`` /
    ``patchedDependencies:`` name versions that are not necessarily
    installed.

    Handles the key shapes of all lockfile generations:

    - v5 (pnpm 6/7): ``/name/1.0.0:``, peer suffix ``_react@18.3.1``
    - v6 (pnpm 8): ``/name@1.0.0:``, peer suffix ``(react@18.3.1)``
    - v9 (pnpm 9+): ``name@1.0.0:``, quoted scoped ``'@scope/pkg@1.0.0':``

    Returns deduplicated list of ``(package_name, version_or_None)``.
    """
    # ponytail: aliased keys (`name@npm:real-pkg@1.0.0`) are skipped -- the
    # resolved target is not derivable from the key alone; parse the
    # `resolution:` field if alias coverage is ever needed.
    name_pattern = r"@[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+|[a-zA-Z0-9_.-]+"
    key_re = re.compile(rf"({name_pattern})[@/](\d+\.\d+\.\d+[0-9A-Za-z.+-]*)")
    results: List[Tuple[str, Optional[str]]] = []
    seen: set = set()
    section: Optional[str] = None
    for line in content.splitlines():
        if line and line[0] not in " \t":
            section = line.split(":", 1)[0].strip().strip("'\"")
            continue
        if section != "packages":
            continue
        stripped = line.strip()
        if ":" not in stripped:
            continue
        # "  '/@scope/pkg@1.0.0(react@18.3.1)':" -> "@scope/pkg@1.0.0"
        key = stripped.split(":", 1)[0].strip("'\"").lstrip("/").split("(", 1)[0]
        m = key_re.match(key)
        # The version must end the key, except for a v5-style "_peer" suffix
        if not m or (m.end() != len(key) and key[m.end()] != "_"):
            continue
        pkg = m.group(1).lower()
        ver = m.group(2)
        if pkg in target_packages and (pkg, ver) not in seen:
            seen.add((pkg, ver))
            results.append((pkg, ver))
    return results


# ── Ecosystem operations ─────────────────────────────────────────────────────


def get_parsers(
    target_packages: Set[str],
) -> Dict[str, Callable[..., List[Tuple[str, Optional[str]]]]]:
    """Return dict of parser-key -> callable with *target_packages* bound."""
    return {
        "package.json": lambda content: parse_package_json(content, target_packages),
        "package-lock.json": lambda content: parse_package_lock_json(content, target_packages),
        "yarn.lock": lambda content: parse_yarn_lock(content, target_packages),
        "pnpm-lock.yaml": lambda content: parse_pnpm_lock(content, target_packages),
    }


def match_file(
    basename: str,
    parsers: Dict[str, Callable[..., List[Tuple[str, Optional[str]]]]],
) -> Optional[Callable[..., List[Tuple[str, Optional[str]]]]]:
    """Given *basename* and a *parsers* dict, return the matching parser or ``None``."""
    if basename == "package-lock.json":
        return parsers.get("package-lock.json")
    if basename == "package.json":
        return parsers.get("package.json")
    if basename == "yarn.lock":
        return parsers.get("yarn.lock")
    if basename == "pnpm-lock.yaml":
        return parsers.get("pnpm-lock.yaml")
    return None


# ── Helpers for local scanning ───────────────────────────────────────────────


def _read_node_module_version(root_dir: str, pkg_name: str) -> Optional[str]:
    """Read version from ``node_modules/{pkg}/package.json`` directly.

    Returns version string or ``None``.
    """
    pkg_json_path = os.path.join(root_dir, "node_modules", pkg_name, "package.json")
    if not os.path.isfile(pkg_json_path):
        return None
    try:
        with open(pkg_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("version")
    except (OSError, ValueError):
        return None


def _check_npm_packages(
    root_dir: str,
    target_packages: Set[str],
    logger: Any = None,
) -> Dict[str, str]:
    """Check installed npm package versions in *root_dir*.

    Tries ``npm list --json --depth=0`` first (accepts returncode 0 or 1),
    then falls back to reading ``node_modules/{pkg}/package.json`` directly.

    Returns ``{package_name: version}`` for detected packages.
    """
    installed: Dict[str, str] = {}

    # Method 1: npm list --json
    if shutil.which("npm"):
        try:
            result = subprocess.run(
                ["npm", "list", "--json", "--depth=0"],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=root_dir,
            )
            if result.returncode in (0, 1) and result.stdout.strip():
                data = json.loads(result.stdout)
                deps = data.get("dependencies", {})
                for pkg_name, info in deps.items():
                    if pkg_name.lower() in target_packages:
                        ver = info.get("version")
                        if ver:
                            installed[pkg_name.lower()] = ver
                            if logger:
                                logger.debug(
                                    f"    npm list 検出: {pkg_name}=={ver}"
                                )
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            pass

    # Method 2: direct read of node_modules/{pkg}/package.json (fallback)
    for pkg in target_packages:
        if pkg in installed:
            continue
        ver = _read_node_module_version(root_dir, pkg)
        if ver:
            installed[pkg] = ver
            if logger:
                logger.debug(f"    node_modules 直接読み取り: {pkg}=={ver}")

    return installed


# ── Local-scanning hooks ─────────────────────────────────────────────────────


def check_installed(
    root_dir: str,
    target_packages: Set[str],
    dep_files: List[str],
    logger: Any = None,
) -> List[Dict[str, Any]]:
    """Detect installed npm packages across all package.json directories.

    Returns list of installed_info dicts with ``"ecosystem": "npm"``.
    """
    installed_info: List[Dict[str, Any]] = []

    # Collect directories that contain a package.json
    npm_dirs: set[str] = set()
    for f in dep_files:
        if os.path.basename(f) == "package.json":
            npm_dirs.add(os.path.dirname(f))

    for npm_dir in sorted(npm_dirs):
        node_modules_dir = os.path.join(npm_dir, "node_modules")
        if not os.path.isdir(node_modules_dir):
            if logger:
                logger.debug(
                    f"    node_modules なし: {npm_dir} (skip npm installed check)"
                )
            continue

        rel_dir = os.path.relpath(npm_dir, root_dir)
        if logger:
            logger.info(f"  npm パッケージを確認中: {rel_dir}")

        npm_installed = _check_npm_packages(npm_dir, target_packages, logger)

        # Filter out entries where version is None
        npm_installed = {k: v for k, v in npm_installed.items() if v is not None}

        if npm_installed:
            installed_info.append(
                {
                    "environment": f"npm:{rel_dir}",
                    "ecosystem": "npm",
                    "python": "(npm)",
                    "packages": npm_installed,
                }
            )

    return installed_info


def find_malicious_dirs(
    root_dir: str,
    malicious_dir_names: List[str],
    logger: Any = None,
) -> List[str]:
    """Walk *root_dir* looking for ``node_modules/{name}`` directories.

    *malicious_dir_names* is a list of package names to search for.

    Returns list of absolute paths.
    """
    found: List[str] = []
    for dirpath, dirnames, _filenames in os.walk(root_dir):
        dirnames[:] = [
            d for d in dirnames if d not in {".git", "__pycache__", ".tox"}
        ]
        if os.path.basename(dirpath) == "node_modules":
            for name in malicious_dir_names:
                malicious_dir = os.path.join(dirpath, name)
                if os.path.isdir(malicious_dir):
                    found.append(malicious_dir)
                    if logger:
                        logger.warning(
                            f"    !! 悪意あるパッケージ検出: {malicious_dir}"
                        )
            # Don't recurse further into node_modules
            dirnames.clear()
    return found


def check_artifacts(
    artifact_paths: Dict[str, List[str]],
    logger: Any = None,
) -> List[Dict[str, str]]:
    """Check platform-specific malware paths.

    *artifact_paths* maps platform names (``"Darwin"``, ``"Linux"``,
    ``"Windows"``) to lists of filesystem paths to probe.

    Returns list of ``{"path": str, "platform": str}`` dicts.
    """
    artifacts: List[Dict[str, str]] = []
    system = platform.system()

    paths_to_check: List[str] = []
    raw_paths = artifact_paths.get(system, [])
    for raw in raw_paths:
        path = os.path.expanduser(raw)
        if system == "Windows":
            # Expand environment variables like %PROGRAMDATA%
            path = os.path.expandvars(path)
        paths_to_check.append(path)

    for path in paths_to_check:
        if os.path.exists(path):
            artifacts.append({"path": path, "platform": system})
            if logger:
                logger.warning(f"    !! マルウェア痕跡検出: {path}")
        else:
            if logger:
                logger.debug(f"    マルウェア痕跡なし: {path}")

    return artifacts


def enrich_findings(
    findings: List[Dict[str, Any]],
    installed_info: List[Dict[str, Any]],
    dep_files: List[str],
    root_dir: str,
    judge_fn: Callable[[str, Optional[str]], Tuple[str, str]],
    logger: Any = None,
) -> None:
    """Enrich dependency-file findings with lockfile / installed versions.

    For each ``package.json`` finding:
    1. Prefer same-directory lockfile version (package-lock.json,
       yarn.lock, or pnpm-lock.yaml).
    2. Fall back to npm installed version from ``check_installed``.
    """
    # Build parsers for lockfile re-parsing (we need target_packages but
    # the lockfile parsers in the parsers dict already have them bound,
    # so we reconstruct from dep_files basenames).
    # Determine all packages we care about from installed_info + findings
    # (loop-invariant: built once, not per lockfile)
    all_targets: Set[str] = set()
    for env in installed_info:
        all_targets.update(env.get("packages", {}).keys())
    for finding in findings:
        pkg_name = finding.get("package")
        if pkg_name:
            all_targets.add(pkg_name)

    # Build lockfile_versions:
    # {directory: {pkg: [(version, lockfile_relpath), ...]}}
    # A lockfile can legitimately pin several versions of one package
    # (direct + transitive), so every version is kept for judgment.
    lockfile_versions: Dict[str, Dict[str, List[Tuple[str, str]]]] = {}
    for f in dep_files:
        basename = os.path.basename(f)
        if basename not in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
            continue
        # We need to parse the lockfile.  Since we don't know target_packages
        # at this level, we parse with a broad set by reading all packages.
        # The caller should have already set up appropriate parsers.
        # Use raw parsers with a broad target set.
        try:
            with open(f, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue

        if basename == "package-lock.json":
            parsed = parse_package_lock_json(content, all_targets)
        elif basename == "yarn.lock":
            parsed = parse_yarn_lock(content, all_targets)
        elif basename == "pnpm-lock.yaml":
            parsed = parse_pnpm_lock(content, all_targets)
        else:
            continue

        lock_dir = os.path.dirname(f)
        if lock_dir not in lockfile_versions:
            lockfile_versions[lock_dir] = {}
        for pkg_name, ver in parsed:
            if ver:
                entry = (ver, os.path.relpath(f, root_dir))
                versions = lockfile_versions[lock_dir].setdefault(pkg_name, [])
                if entry not in versions:
                    versions.append(entry)

    for finding in findings:
        if finding["source"] != "dependency_file":
            continue

        file_basename = os.path.basename(finding["file_path"])
        if file_basename != "package.json":
            continue

        pkg = finding["package"]

        # 1. Prefer lockfile version from the same directory
        finding_abs = os.path.join(root_dir, finding["file_path"])
        finding_dir = os.path.dirname(finding_abs)
        dir_locks = lockfile_versions.get(finding_dir, {})
        if pkg in dir_locks:
            # Judge every pinned version and keep the most severe: a
            # vulnerable copy must never be masked by a safe sibling
            # version that happens to appear first in the lockfile.
            best = None
            for lock_ver, lock_file in dir_locks[pkg]:
                result = judge_fn(pkg, lock_ver)
                if best is None or most_severe(best[0], result) is result:
                    best = (result, lock_ver, lock_file)
            if best is None:
                continue
            (verdict, judge_note), lock_ver, lock_file = best
            finding["version"] = lock_ver
            finding["verdict"] = verdict
            finding["note"] = (
                f"{judge_note}（lockfile {lock_file} による実バージョン: {lock_ver}）"
            )
            if logger:
                logger.info(
                    f"    lockfile 補完: {pkg} → {lock_ver} ({lock_file}) → {verdict}"
                )
            continue

        # 2. Fallback: npm installed version from node_modules
        npm_env_key = f"npm:{os.path.relpath(finding_dir, root_dir)}"
        for env in installed_info:
            if env["environment"] == npm_env_key:
                npm_pkgs = env["packages"]
                if pkg in npm_pkgs:
                    actual_ver = npm_pkgs[pkg]
                    finding["version"] = actual_ver
                    verdict, judge_note = judge_fn(pkg, actual_ver)
                    finding["verdict"] = verdict
                    finding["note"] = (
                        f"{judge_note}"
                        f"（node_modules の実バージョン: {actual_ver}, {npm_env_key}）"
                    )
                    if logger:
                        logger.info(
                            f"    npm バージョン補完: {pkg} → {actual_ver}"
                            f" ({npm_env_key}) → {verdict}"
                        )
                break

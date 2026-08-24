"""Python ecosystem parsers and local-scanning helpers.

All functions are package-name independent -- ``target_packages`` is always
passed in as a parameter rather than referencing module-level constants.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# ── File-matching patterns ───────────────────────────────────────────────────

FILE_PATTERNS_GLOB: List[str] = [
    "**/requirements*.txt",
    "**/pyproject.toml",
    "**/Pipfile",
    "**/Pipfile.lock",
    "**/poetry.lock",
    "**/setup.py",
    "**/setup.cfg",
    "**/Dockerfile*",
]

FILE_PATTERNS_REGEX: List[re.Pattern[str]] = [
    re.compile(r"(^|/)requirements[^/]*\.txt$", re.IGNORECASE),
    re.compile(r"(^|/)pyproject\.toml$"),
    re.compile(r"(^|/)Pipfile$"),
    re.compile(r"(^|/)Pipfile\.lock$"),
    re.compile(r"(^|/)poetry\.lock$"),
    re.compile(r"(^|/)setup\.py$"),
    re.compile(r"(^|/)setup\.cfg$"),
    re.compile(r"(^|/)[Dd]ockerfile[^/]*$"),
]

# ── Parser functions ─────────────────────────────────────────────────────────


def parse_requirements_txt(
    content: str,
    target_packages: Set[str],
) -> List[Tuple[str, Optional[str]]]:
    """Parse ``requirements.txt`` format.

    Returns list of ``(package_name, version_or_None)``.
    """
    results: List[Tuple[str, Optional[str]]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Remove inline comments
        line = line.split("#")[0].strip()
        m = re.match(
            r"^([a-zA-Z0-9_-]+)\s*(?:[=~!<>]=?\s*([0-9][0-9a-zA-Z._-]*))?", line
        )
        if m:
            pkg = m.group(1).lower().replace("-", "_")
            ver = m.group(2)
            if pkg.replace("_", "-") in target_packages or pkg in target_packages:
                results.append((pkg, ver))
    return results


def parse_pyproject_toml(
    content: str,
    target_packages: Set[str],
) -> List[Tuple[str, Optional[str]]]:
    """Parse ``pyproject.toml`` for dependencies (simple regex-based)."""
    results: List[Tuple[str, Optional[str]]] = []
    for pkg in target_packages:
        patterns = [
            rf'["\']({re.escape(pkg)})\s*(?:[=~!<>]=?\s*([0-9][0-9a-zA-Z._-]*))?["\']',
            rf"^{re.escape(pkg)}\s*=\s*[\"']([^\"']*)[\"']",
            rf"^{re.escape(pkg)}\s*=\s*\{{[^}}]*version\s*=\s*[\"']([^\"']*)[\"']",
        ]
        for pattern in patterns:
            for m in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                groups = m.groups()
                if len(groups) >= 2:
                    ver = groups[1]
                else:
                    ver_str = groups[0] if groups else None
                    ver_m = re.search(
                        r"[=~!<>]=?\s*([0-9][0-9a-zA-Z._-]*)", ver_str or ""
                    )
                    ver = ver_m.group(1) if ver_m else None
                results.append((pkg, ver))
    return results


def parse_pipfile(
    content: str,
    target_packages: Set[str],
) -> List[Tuple[str, Optional[str]]]:
    """Parse ``Pipfile`` format."""
    results: List[Tuple[str, Optional[str]]] = []
    for pkg in target_packages:
        patterns = [
            rf"^{re.escape(pkg)}\s*=\s*[\"']([^\"']*)[\"']",
            rf"^{re.escape(pkg)}\s*=\s*[\"']?\*[\"']?",
            rf"^{re.escape(pkg)}\s*=\s*\{{[^}}]*version\s*=\s*[\"']([^\"']*)[\"']",
        ]
        for pattern in patterns:
            for m in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                groups = m.groups()
                if groups and groups[0]:
                    ver_m = re.search(r"[0-9][0-9a-zA-Z._-]*", groups[0])
                    ver = ver_m.group(0) if ver_m else None
                else:
                    ver = None
                results.append((pkg, ver))
    return results


def parse_pipfile_lock(
    content: str,
    target_packages: Set[str],
) -> List[Tuple[str, Optional[str]]]:
    """Parse ``Pipfile.lock`` (JSON format)."""
    results: List[Tuple[str, Optional[str]]] = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return results
    for section in ["default", "develop"]:
        if section not in data:
            continue
        for pkg_name, info in data[section].items():
            normalized = pkg_name.lower().replace("-", "_")
            if normalized in target_packages or pkg_name.lower() in target_packages:
                ver = info.get("version", "").lstrip("=")
                results.append((normalized, ver if ver else None))
    return results


def parse_poetry_lock(
    content: str,
    target_packages: Set[str],
) -> List[Tuple[str, Optional[str]]]:
    """Parse ``poetry.lock`` (TOML format, regex-based)."""
    results: List[Tuple[str, Optional[str]]] = []
    blocks = re.split(r"\[\[package\]\]", content)
    for block in blocks:
        name_m = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
        ver_m = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
        if name_m:
            pkg = name_m.group(1).lower().replace("-", "_")
            if pkg in target_packages:
                ver = ver_m.group(1) if ver_m else None
                results.append((pkg, ver))
    return results


def parse_setup_py(
    content: str,
    target_packages: Set[str],
) -> List[Tuple[str, Optional[str]]]:
    """Parse ``setup.py`` for ``install_requires``."""
    results: List[Tuple[str, Optional[str]]] = []
    m = re.search(r"install_requires\s*=\s*\[([^\]]*)\]", content, re.DOTALL)
    if m:
        requires_str = m.group(1)
        for pkg in target_packages:
            pkg_m = re.search(
                rf'["\']({re.escape(pkg)})\s*(?:[=~!<>]=?\s*([0-9][0-9a-zA-Z._-]*))?["\']',
                requires_str,
                re.IGNORECASE,
            )
            if pkg_m:
                ver = pkg_m.group(2)
                results.append((pkg, ver))
    return results


def parse_setup_cfg(
    content: str,
    target_packages: Set[str],
) -> List[Tuple[str, Optional[str]]]:
    """Parse ``setup.cfg`` for ``install_requires``."""
    results: List[Tuple[str, Optional[str]]] = []
    in_install = False
    for line in content.splitlines():
        if line.strip() == "install_requires =":
            in_install = True
            continue
        if in_install:
            if line and not line[0].isspace():
                break
            stripped = line.strip()
            m = re.match(
                r"([a-zA-Z0-9_-]+)\s*(?:[=~!<>]=?\s*([0-9][0-9a-zA-Z._-]*))?",
                stripped,
            )
            if m:
                pkg = m.group(1).lower().replace("-", "_")
                if pkg in target_packages:
                    results.append((pkg, m.group(2)))
    return results


def parse_dockerfile(
    content: str,
    target_packages: Set[str],
) -> List[Tuple[str, Optional[str]]]:
    """Parse ``Dockerfile`` for ``pip install`` commands."""
    results: List[Tuple[str, Optional[str]]] = []
    for line in content.splitlines():
        if "pip install" not in line.lower():
            continue
        for pkg in target_packages:
            m = re.search(
                rf"({re.escape(pkg)})\s*(?:[=~!<>]=?\s*([0-9][0-9a-zA-Z._-]*))?",
                line,
                re.IGNORECASE,
            )
            if m:
                results.append((pkg, m.group(2)))
    return results


# ── Ecosystem operations ─────────────────────────────────────────────────────


def get_parsers(
    target_packages: Set[str],
) -> Dict[str, Callable[..., List[Tuple[str, Optional[str]]]]]:
    """Return dict of parser-key -> callable with *target_packages* bound."""
    return {
        "requirements": lambda content: parse_requirements_txt(content, target_packages),
        "pyproject.toml": lambda content: parse_pyproject_toml(content, target_packages),
        "Pipfile": lambda content: parse_pipfile(content, target_packages),
        "Pipfile.lock": lambda content: parse_pipfile_lock(content, target_packages),
        "poetry.lock": lambda content: parse_poetry_lock(content, target_packages),
        "setup.py": lambda content: parse_setup_py(content, target_packages),
        "setup.cfg": lambda content: parse_setup_cfg(content, target_packages),
        "Dockerfile": lambda content: parse_dockerfile(content, target_packages),
    }


def match_file(
    basename: str,
    parsers: Dict[str, Callable[..., List[Tuple[str, Optional[str]]]]],
) -> Optional[Callable[..., List[Tuple[str, Optional[str]]]]]:
    """Given *basename* and a *parsers* dict, return the matching parser or ``None``."""
    if basename == "Pipfile.lock":
        return parsers.get("Pipfile.lock")
    if basename == "Pipfile":
        return parsers.get("Pipfile")
    if "requirements" in basename.lower() and basename.endswith(".txt"):
        return parsers.get("requirements")
    if basename == "pyproject.toml":
        return parsers.get("pyproject.toml")
    if basename == "poetry.lock":
        return parsers.get("poetry.lock")
    if basename == "setup.py":
        return parsers.get("setup.py")
    if basename == "setup.cfg":
        return parsers.get("setup.cfg")
    if "Dockerfile" in basename or "dockerfile" in basename:
        return parsers.get("Dockerfile")
    return None


# ── Helper functions for installed-package detection ─────────────────────────


def _parse_freeze_output(
    output: str,
    target_packages: Set[str],
) -> Dict[str, str]:
    """Parse ``pip freeze`` / ``uv pip freeze`` output into ``{package: version}``."""
    installed: Dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if "==" not in line:
            continue
        parts = line.split("==", 1)
        pkg = parts[0].lower().replace("-", "_")
        ver = parts[1]
        if pkg in target_packages:
            installed[pkg] = ver
    return installed


def _check_installed_packages(
    python_executable: Optional[str] = None,
    venv_path: Optional[str] = None,
    logger: Any = None,
    target_packages: Optional[Set[str]] = None,
) -> Dict[str, str]:
    """Check installed packages via ``uv pip freeze``, ``pip freeze``, or site-packages.

    Tries multiple methods in order:
    1. ``uv pip freeze --python {python}`` (if uv is available)
    2. ``python -m pip freeze``
    3. Direct reading of site-packages (fallback)

    Returns ``{package_name: version}`` for detected packages.
    """
    packages = target_packages or set()
    python = python_executable or sys.executable

    # Method 1: uv pip freeze
    if shutil.which("uv"):
        uv_cmd = ["uv", "pip", "freeze", "--python", python]
        try:
            result = subprocess.run(
                uv_cmd, capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                if logger:
                    logger.debug("    uv pip freeze 成功")
                return _parse_freeze_output(result.stdout, packages)
            if logger:
                logger.debug(f"    uv pip freeze 失敗: {result.stderr.strip()}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    # Method 2: python -m pip freeze
    pip_cmd = [python, "-m", "pip", "freeze"]
    try:
        result = subprocess.run(
            pip_cmd, capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            if logger:
                logger.debug("    pip freeze 成功")
            return _parse_freeze_output(result.stdout, packages)
        if logger:
            logger.debug(f"    pip freeze 失敗: {result.stderr.strip()}")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        if logger:
            logger.debug(f"    pip freeze 失敗: {e}")

    # Method 3: Read .dist-info directories in site-packages
    search_root = venv_path or os.path.dirname(os.path.dirname(python))
    installed = _check_site_packages(search_root, logger, packages)
    if installed:
        return installed

    return {}


def _check_site_packages(
    root: str,
    logger: Any = None,
    target_packages: Optional[Set[str]] = None,
) -> Dict[str, str]:
    """Scan ``site-packages`` directories for installed target packages."""
    packages = target_packages or set()
    installed: Dict[str, str] = {}
    for dirpath, dirnames, _filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        if not dirpath.endswith("site-packages"):
            continue
        if logger:
            logger.debug(f"    site-packages スキャン: {dirpath}")
        for entry in os.listdir(dirpath):
            if not entry.endswith(".dist-info"):
                continue
            parts = entry[: -len(".dist-info")].rsplit("-", 1)
            if len(parts) != 2:
                continue
            pkg_name = parts[0].lower().replace("-", "_")
            pkg_ver = parts[1]
            if pkg_name in packages:
                installed[pkg_name] = pkg_ver
                if logger:
                    logger.debug(f"    dist-info 検出: {pkg_name}=={pkg_ver}")
        break  # Only check the first site-packages found at this level
    return installed


def _find_venvs(root_dir: str) -> List[Tuple[str, str]]:
    """Find Python virtual environments under *root_dir*.

    Returns list of ``(venv_path, python_executable)`` tuples.
    """
    venvs: List[Tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [
            d
            for d in dirnames
            if d not in {".git", "node_modules", "__pycache__", ".tox"}
        ]
        if "pyvenv.cfg" in filenames:
            bin_dir = os.path.join(dirpath, "bin")
            scripts_dir = os.path.join(dirpath, "Scripts")  # Windows
            if os.path.isdir(bin_dir):
                python_path = os.path.join(bin_dir, "python")
                if os.path.isfile(python_path):
                    venvs.append((dirpath, python_path))
            elif os.path.isdir(scripts_dir):
                python_path = os.path.join(scripts_dir, "python.exe")
                if os.path.isfile(python_path):
                    venvs.append((dirpath, python_path))
            # Don't descend further into venv
            dirnames.clear()
    return venvs


# ── Local-scanning hooks ─────────────────────────────────────────────────────


def check_installed(
    root_dir: str,
    target_packages: Set[str],
    logger: Any = None,
) -> List[Dict[str, Any]]:
    """Detect target packages in system Python and virtual envs.

    Returns list of installed_info dicts with ``"ecosystem": "python"``.
    """
    installed_info: List[Dict[str, Any]] = []

    # System Python
    if logger:
        logger.info(
            "  システム Python のインストール済みパッケージを確認中..."
        )
        logger.debug(f"    Python: {sys.executable}")

    system_installed = _check_installed_packages(logger=logger, target_packages=target_packages)
    if system_installed:
        installed_info.append(
            {
                "environment": "system",
                "ecosystem": "python",
                "python": sys.executable,
                "packages": system_installed,
            }
        )

    # Virtual environments
    venvs = _find_venvs(root_dir)
    if logger:
        logger.debug(f"  仮想環境 {len(venvs)}件検出")

    for venv_path, python_path in venvs:
        rel_venv = os.path.relpath(venv_path, root_dir)
        if logger:
            logger.info(f"  仮想環境を確認中: {rel_venv}")
            logger.debug(f"    Python: {python_path}")

        venv_installed = _check_installed_packages(
            python_path, venv_path, logger, target_packages
        )
        if venv_installed:
            installed_info.append(
                {
                    "environment": rel_venv,
                    "ecosystem": "python",
                    "python": python_path,
                    "packages": venv_installed,
                }
            )

    return installed_info


def enrich_findings(
    findings: List[Dict[str, Any]],
    installed_info: List[Dict[str, Any]],
    dep_files: List[str],
    root_dir: str,
    judge_fn: Callable[[str, Optional[str]], Tuple[str, str]],
    logger: Any = None,
) -> None:
    """Enrich unversioned Python dependency_file findings with pip freeze versions."""
    # Build map of all installed Python packages across environments
    all_installed_pkgs: Dict[str, Tuple[str, str]] = {}
    for env in installed_info:
        if env.get("ecosystem") != "python":
            continue
        for pkg, ver in env["packages"].items():
            all_installed_pkgs[pkg] = (ver, env["environment"])

    for finding in findings:
        if finding["source"] != "dependency_file":
            continue
        # Only enrich Python files (skip package.json etc.)
        file_basename = os.path.basename(finding["file_path"])
        if file_basename == "package.json":
            continue

        pkg = finding["package"]
        if pkg in all_installed_pkgs:
            actual_ver, env_label = all_installed_pkgs[pkg]
            if not finding["version"]:
                finding["version"] = actual_ver
                verdict, judge_note = judge_fn(pkg, actual_ver)
                finding["verdict"] = verdict
                finding["note"] = (
                    f"{judge_note}（バージョン未指定だが実環境では"
                    f" {actual_ver} がインストール済み: {env_label}）"
                )
                if logger:
                    logger.info(
                        f"    バージョン補完: {pkg} → {actual_ver}"
                        f" ({env_label}) → {verdict}"
                    )

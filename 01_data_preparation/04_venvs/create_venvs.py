"""
Create virtual environments for each Django version in the dataset.

For each unique Django major.minor version found in the enriched dataset,
this script:
  1. Resolves the list of supported Python versions (from the dataset)
  2. Uses pyenv to install the latest patch of the first supported Python version
  3. Creates a venv using that Python, falling back to the next version on failure
  4. Installs the matching Django release into the venv from the local repo

The venvs are placed under:  03_venvs/django_venvs/django-<major>.<minor>/

Prerequisites:
  - pyenv installed and on PATH
  - Build dependencies for pyenv (gcc, zlib-dev, libffi-dev, etc.)
  - The enriched dataset at ../02_add_python_versions/data/dataset_with_py_versions.jsonl
  - The Django git repo at ../../repositories/django

Usage:
    python create_venvs.py              # create all venvs
    python create_venvs.py --only 4.2   # create venv for Django 4.2 only
    python create_venvs.py --skip-install-python  # skip pyenv install step
"""

import json
import os
import re
import subprocess
import sys
import logging
import argparse
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
ENRICHED_DATA = SCRIPT_DIR / ".." / "02_add_python_versions" / "data" / "dataset_with_py_versions.jsonl"
DJANGO_REPO = SCRIPT_DIR / ".." / ".." / "repositories" / "django"
VENVS_DIR = SCRIPT_DIR / "django_venvs"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_DIR = SCRIPT_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "create_venvs.log", mode="w"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Mapping: Python minor -> latest patch available in pyenv
# We resolve this dynamically from `pyenv install --list` at startup.
# ---------------------------------------------------------------------------
PYENV_LATEST_PATCH = {}   # e.g. {"3.12": "3.12.12"}


def resolve_pyenv_versions():
    """Populate PYENV_LATEST_PATCH from pyenv install --list."""
    try:
        out = subprocess.check_output(
            ["pyenv", "install", "--list"], stderr=subprocess.DEVNULL
        ).decode()
    except Exception as e:
        logger.error(f"Failed to run `pyenv install --list`: {e}")
        sys.exit(1)

    for line in out.splitlines():
        line = line.strip()
        # Match only standard CPython releases (e.g. 3.12.4, 2.7.18)
        m = re.match(r"^(\d+\.\d+)\.(\d+)$", line)
        if m:
            minor = m.group(1)
            # Keep the highest patch we see (list is sorted ascending)
            PYENV_LATEST_PATCH[minor] = line

    logger.info(f"Resolved {len(PYENV_LATEST_PATCH)} Python minor versions from pyenv")


def ensure_python_installed(minor_version: str, skip_install: bool = False) -> Optional[str]:
    """
    Ensure a Python version is installed via pyenv.
    Returns the full patch version string (e.g. '3.12.12') or None on failure.
    """
    full = PYENV_LATEST_PATCH.get(minor_version)
    if not full:
        logger.warning(f"  Python {minor_version} not available in pyenv")
        return None

    # Check if already installed
    try:
        installed = subprocess.check_output(
            ["pyenv", "versions", "--bare"], stderr=subprocess.DEVNULL
        ).decode().splitlines()
        if full in [v.strip() for v in installed]:
            logger.info(f"  Python {full} already installed")
            return full
    except Exception:
        pass

    if skip_install:
        logger.warning(f"  Python {full} not installed and --skip-install-python set")
        return None

    logger.info(f"  Installing Python {full} via pyenv...")
    try:
        subprocess.check_call(
            ["pyenv", "install", full],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        logger.info(f"  Python {full} installed successfully")
        return full
    except subprocess.CalledProcessError as e:
        logger.error(f"  Failed to install Python {full}: {e}")
        return None


def get_python_executable(full_version: str) -> Optional[str]:
    """Get the path to a pyenv-installed Python executable."""
    pyenv_root = os.environ.get("PYENV_ROOT", os.path.expanduser("~/.pyenv"))
    exe = Path(pyenv_root) / "versions" / full_version / "bin" / "python"
    if exe.exists():
        return str(exe)

    # Fallback: ask pyenv
    try:
        result = subprocess.check_output(
            ["pyenv", "prefix", full_version], stderr=subprocess.DEVNULL
        ).decode().strip()
        exe = Path(result) / "bin" / "python"
        if exe.exists():
            return str(exe)
    except Exception:
        pass

    return None


def get_django_pip_version(django_minor: str) -> str:
    """
    Map a Django minor version (e.g. '4.2') to the pip install specifier.
    We install the latest patch of that minor series.
    """
    # For the latest development versions that may not be on PyPI yet,
    # we'll install from the local repo checkout at the tag.
    return f"Django>={django_minor},<{next_minor(django_minor)}"


def next_minor(version: str) -> str:
    """'4.2' -> '4.3', '1.11' -> '1.12'."""
    parts = version.split(".")
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts)


def is_python2(minor_version: str) -> bool:
    """Check if a minor version string is Python 2.x."""
    return minor_version.startswith("2.")


def ensure_virtualenv(python_exe: str) -> bool:
    """Ensure virtualenv is available for a Python 2.x interpreter."""
    try:
        subprocess.check_call(
            [python_exe, "-c", "import virtualenv"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except subprocess.CalledProcessError:
        pass

    # Try to install virtualenv via pip
    logger.info(f"  Installing virtualenv for {python_exe}...")
    try:
        subprocess.check_call(
            [python_exe, "-m", "pip", "install", "virtualenv"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        return True
    except subprocess.CalledProcessError:
        pass

    # Try using easy_install as last resort (available in old Pythons)
    try:
        subprocess.check_call(
            [python_exe, "-m", "easy_install", "virtualenv"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    logger.warning(f"  Could not install virtualenv for {python_exe}")
    return False


def create_virtualenv_py2(python_exe: str, venv_path: Path) -> bool:
    """Create a virtual environment using virtualenv (for Python 2.x)."""
    try:
        subprocess.check_call(
            [python_exe, "-m", "virtualenv", str(venv_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"  virtualenv creation failed: {e}")
        return False


def create_venv_py3(python_exe: str, venv_path: Path) -> bool:
    """Create a virtual environment using venv (for Python 3.3+)."""
    try:
        subprocess.check_call(
            [python_exe, "-m", "venv", str(venv_path)],
            stderr=subprocess.PIPE,
        )
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"  venv creation failed: {e}")
        return False


def create_venv(django_minor: str, python_versions: list,
                skip_install: bool = False) -> bool:
    """
    Create a venv for a Django minor version.
    Tries each Python version in order until one works.
    Uses virtualenv for Python 2.x, venv for Python 3.x.
    Returns True on success.
    """
    venv_path = VENVS_DIR / f"django-{django_minor}"

    if venv_path.exists():
        logger.info(f"  Venv already exists at {venv_path}, skipping")
        return True

    for py_minor in python_versions:
        logger.info(f"  Trying Python {py_minor} for Django {django_minor}...")
        full = ensure_python_installed(py_minor, skip_install)
        if not full:
            continue

        python_exe = get_python_executable(full)
        if not python_exe:
            logger.warning(f"  Could not find executable for Python {full}")
            continue

        # Create the virtual environment
        logger.info(f"  Creating venv at {venv_path} with {python_exe}...")
        if is_python2(py_minor):
            # Python 2: use virtualenv
            if not ensure_virtualenv(python_exe):
                logger.warning(f"  No virtualenv available for Python {full}")
                continue
            venv_ok = create_virtualenv_py2(python_exe, venv_path)
        else:
            # Python 3: use venv module
            venv_ok = create_venv_py3(python_exe, venv_path)

        if not venv_ok:
            subprocess.run(["rm", "-rf", str(venv_path)], check=False)
            continue

        # Locate pip and python inside the venv
        venv_pip = venv_path / "bin" / "pip"
        venv_python = venv_path / "bin" / "python"

        # Upgrade pip (best-effort, old Pythons may not support latest pip)
        try:
            subprocess.check_call(
                [str(venv_python), "-m", "pip", "install", "--upgrade", "pip"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError:
            logger.warning(f"  Could not upgrade pip (non-fatal)")

        # Install Django — try PyPI first, fall back to local repo tag
        django_spec = get_django_pip_version(django_minor)
        logger.info(f"  Installing {django_spec} into venv...")
        install_ok = False
        try:
            subprocess.check_call(
                [str(venv_pip), "install", django_spec],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            install_ok = True
        except subprocess.CalledProcessError:
            logger.warning(f"  PyPI install of {django_spec} failed, trying local repo tag...")

        if not install_ok:
            # Install from local repo at the tag
            tag = django_minor
            try:
                subprocess.check_call(
                    ["git", "checkout", tag],
                    cwd=str(DJANGO_REPO),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                subprocess.check_call(
                    [str(venv_pip), "install", "-e", str(DJANGO_REPO)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                install_ok = True
            except subprocess.CalledProcessError as e:
                logger.error(f"  Local repo install at tag {tag} also failed: {e}")

        if not install_ok:
            # Last resort for very old Django: copy the repo at the tag into the
            # venv's site-packages so it's importable without pip
            tag = django_minor
            try:
                subprocess.check_call(
                    ["git", "checkout", tag],
                    cwd=str(DJANGO_REPO),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                # Find site-packages
                site_pkg = subprocess.check_output(
                    [str(venv_python), "-c",
                     "import site; print(site.getsitepackages()[0] if hasattr(site,'getsitepackages') else site.getusersitepackages())"],
                    stderr=subprocess.DEVNULL,
                ).decode().strip()
                django_src = DJANGO_REPO / "django"
                target = Path(site_pkg) / "django"
                if django_src.exists():
                    subprocess.check_call(
                        ["cp", "-r", str(django_src), str(target)],
                    )
                    install_ok = True
                    logger.info(f"  Installed Django via direct copy to {target}")
            except Exception as e:
                logger.error(f"  Direct copy install also failed: {e}")

        if install_ok:
            # Verify Django is importable
            try:
                dj_ver = subprocess.check_output(
                    [str(venv_python), "-c", "import django; print(django.get_version())"],
                    stderr=subprocess.DEVNULL,
                ).decode().strip()
                method = "virtualenv" if is_python2(py_minor) else "venv"
                logger.info(f"  SUCCESS: django-{django_minor} venv created "
                            f"(Python {full}, Django {dj_ver}, via {method})")
                # Write a metadata file for reference
                meta = {
                    "django_minor": django_minor,
                    "django_installed": dj_ver,
                    "python_full": full,
                    "python_minor": py_minor,
                    "python_exe": python_exe,
                    "venv_path": str(venv_path),
                    "venv_method": method,
                }
                with open(venv_path / "venv_meta.json", "w") as f:
                    json.dump(meta, f, indent=2)
                return True
            except Exception as e:
                logger.error(f"  Django import verification failed: {e}")

        # If we got here, this Python version didn't work — clean up and try next
        logger.warning(f"  Python {full} didn't work for Django {django_minor}, trying next...")
        subprocess.run(["rm", "-rf", str(venv_path)], check=False)

    logger.error(f"  FAILED: Could not create venv for Django {django_minor} "
                 f"with any of {python_versions}")
    return False


def load_version_map() -> dict[str, list[str]]:
    """
    Load the enriched dataset and build a mapping of
    Django minor version -> list of supported Python minor versions.
    
    Python versions are sorted with the latest Python version first
    (best compatibility with modern tooling).
    """
    if not ENRICHED_DATA.exists():
        logger.error(f"Enriched dataset not found: {ENRICHED_DATA}")
        sys.exit(1)

    version_map = {}
    with open(ENRICHED_DATA) as f:
        for line in f:
            if not line.strip():
                continue
            record = json.loads(line)
            for fv in record.get("django", {}).get("fixed_versions", []):
                ver = fv.get("version", "")
                m = re.match(r"Django\s+(\d+\.\d+)", ver)
                if m:
                    tag = m.group(1)
                    py_versions = fv.get("supported_python_versions", [])
                    if tag not in version_map and py_versions:
                        # Sort: latest Python first (better tooling support)
                        sorted_versions = sorted(
                            py_versions,
                            key=lambda v: [int(p) for p in v.split(".")],
                            reverse=True,
                        )
                        # Practical fallback: if only old Python 2.x versions
                        # are listed (2.3-2.6), add 2.7 as a fallback — these
                        # Django versions do run on 2.7, and 2.7 is the only
                        # Python 2.x with reliable virtualenv/pip support.
                        if all(v.startswith("2.") for v in sorted_versions):
                            if "2.7" not in sorted_versions:
                                sorted_versions.insert(0, "2.7")
                                logger.info(
                                    f"  Added Python 2.7 as practical fallback "
                                    f"for Django {tag}"
                                )
                        version_map[tag] = sorted_versions

    return version_map


def main():
    parser = argparse.ArgumentParser(description="Create Django venvs for CVE testing")
    parser.add_argument("--only", type=str, help="Only create venv for this Django version (e.g. 4.2)")
    parser.add_argument("--skip-install-python", action="store_true",
                        help="Skip pyenv install; only use already-installed Python versions")
    args = parser.parse_args()

    VENVS_DIR.mkdir(parents=True, exist_ok=True)

    resolve_pyenv_versions()
    version_map = load_version_map()

    if args.only:
        if args.only not in version_map:
            logger.error(f"Django {args.only} not found in dataset")
            sys.exit(1)
        version_map = {args.only: version_map[args.only]}

    logger.info(f"Creating venvs for {len(version_map)} Django versions...")
    logger.info(f"Venvs directory: {VENVS_DIR}")

    results = {"success": [], "failed": []}

    for django_minor in sorted(version_map.keys(),
                                key=lambda v: [int(p) for p in v.split(".")]):
        py_versions = version_map[django_minor]
        logger.info(f"\n{'='*60}")
        logger.info(f"Django {django_minor} (Python candidates: {py_versions})")
        logger.info(f"{'='*60}")

        ok = create_venv(django_minor, py_versions, args.skip_install_python)
        if ok:
            results["success"].append(django_minor)
        else:
            results["failed"].append(django_minor)

    # Summary
    logger.info(f"\n{'='*60}")
    logger.info("SUMMARY")
    logger.info(f"{'='*60}")
    logger.info(f"Success: {len(results['success'])}/{len(version_map)}")
    for v in results["success"]:
        logger.info(f"  ✓ Django {v}")
    if results["failed"]:
        logger.info(f"Failed:  {len(results['failed'])}/{len(version_map)}")
        for v in results["failed"]:
            logger.info(f"  ✗ Django {v}")

    # Write summary JSON
    summary_path = VENVS_DIR / "summary.json"
    with open(summary_path, "w") as f:
        json.dump(results, f, indent=2)
    logger.info(f"\nSummary written to {summary_path}")


if __name__ == "__main__":
    main()

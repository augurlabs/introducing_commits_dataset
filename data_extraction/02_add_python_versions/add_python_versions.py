"""
Enrich the dataset with supported Python versions for each Django fixed version.

Reads the original JSONL dataset, resolves the supported Python versions for
each Django release tag from the repo's packaging metadata (pyproject.toml,
setup.cfg, or setup.py), and writes an enriched copy.

Usage:
    python enrich_python_versions.py
"""

import json
import re
import subprocess
import os
import sys
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

REPO_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "repositories", "django")
INPUT_FILE = os.path.join(os.path.dirname(__file__), "..", "scraping", "data", "original_full_datatest.jsonl")
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "data", "enriched_datatest.jsonl")

# Early Django releases had no Python version classifiers in their packaging files.
# These are sourced from the official Django FAQ / release notes:
# https://docs.djangoproject.com/en/dev/faq/install/
KNOWN_PYTHON_VERSIONS = {
    "0.90": {"python_versions": ["2.3"], "source": "django docs (no classifiers in repo)"},
    "0.91": {"python_versions": ["2.3"], "source": "django docs (no classifiers in repo)"},
    "0.95": {"python_versions": ["2.3", "2.4"], "source": "django docs (no classifiers in repo)"},
    "0.96": {"python_versions": ["2.3", "2.4", "2.5"], "source": "django docs (no classifiers in repo)"},
    "1.0":  {"python_versions": ["2.3", "2.4", "2.5", "2.6"], "source": "django docs (no classifiers in repo)"},
    "1.1":  {"python_versions": ["2.3", "2.4", "2.5", "2.6"], "source": "django docs (no classifiers in repo)"},
    "1.2":  {"python_versions": ["2.4", "2.5", "2.6", "2.7"], "source": "django docs (no classifiers in repo)"},
}

# Cache so we only look up each tag once
_cache = {}


def extract_version_tag(version_string):
    """
    Normalize 'Django X.Y', 'Django X.Y.Z', 'Django X.Y:' etc. to 'X.Y'
    for use as a git tag.
    """
    m = re.match(r"Django\s+(\d+\.\d+)", version_string)
    return m.group(1) if m else None


def get_python_versions(tag):
    """
    Look up the supported Python versions for a Django release tag.

    Checks pyproject.toml -> setup.cfg -> setup.py for
    'Programming Language :: Python :: X.Y' classifiers.

    Returns:
        dict with 'python_versions' (list[str]) and 'source' (str).
    """
    if tag in _cache:
        return _cache[tag]

    if tag in KNOWN_PYTHON_VERSIONS:
        _cache[tag] = KNOWN_PYTHON_VERSIONS[tag]
        return _cache[tag]

    search_files = ["pyproject.toml", "setup.cfg", "setup.py"]
    for filename in search_files:
        try:
            content = subprocess.check_output(
                ["git", "show", f"{tag}:{filename}"],
                cwd=REPO_PATH,
                stderr=subprocess.DEVNULL,
            ).decode("utf-8")
            versions = re.findall(
                r"Programming Language :: Python :: (\d+\.\d+)", content
            )
            if versions:
                result = {
                    "python_versions": sorted(set(versions)),
                    "source": f"git show {tag}:{filename}",
                }
                _cache[tag] = result
                return result
        except subprocess.CalledProcessError:
            continue

    result = {"python_versions": [], "source": "not found"}
    _cache[tag] = result
    return result


def main():
    if not os.path.isdir(REPO_PATH):
        logger.error(f"Django repo not found at {os.path.abspath(REPO_PATH)}")
        sys.exit(1)

    if not os.path.exists(INPUT_FILE):
        logger.error(f"Input file not found: {os.path.abspath(INPUT_FILE)}")
        sys.exit(1)

    records = []
    with open(INPUT_FILE, "r") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    logger.info(f"Loaded {len(records)} records from {INPUT_FILE}")

    for i, record in enumerate(records):
        cve_id = record.get("cve", {}).get("id", "unknown")
        fixed_versions = record.get("django", {}).get("fixed_versions", [])

        for fv in fixed_versions:
            tag = extract_version_tag(fv.get("version", ""))
            if tag:
                info = get_python_versions(tag)
                fv["supported_python_versions"] = info["python_versions"]
                fv["python_versions_source"] = info["source"]
            else:
                fv["supported_python_versions"] = []
                fv["python_versions_source"] = "could not parse version tag"
                logger.warning(
                    f"  {cve_id}: Could not parse version string '{fv.get('version')}'"
                )

        if (i + 1) % 25 == 0:
            logger.info(f"  Processed {i + 1}/{len(records)} records...")

    with open(OUTPUT_FILE, "w") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")

    logger.info(f"Wrote {len(records)} enriched records to {OUTPUT_FILE}")
    logger.info(f"Resolved Python versions for {len(_cache)} unique Django tags")


if __name__ == "__main__":
    main()

"""
Script Objective:
-----------------
This script is designed to verify if a security patch applied to an older version of Django
is identical to the patch applied to the stable/main version for the same CVE.

Background:
-----------
When Django releases security patches, they often backport the fix to supported older versions.
Sometimes these backports are identical (cherry-picked), and sometimes they require modification 
to fit the older codebase.
Knowing if a patch is identical helps in understanding the spread of the vulnerability and 
the consistency of the fix.

Process:
--------
1.  Read the `data.json` file to get the list of CVEs and their associated patches (commit hashes).
2.  For each CVE, identify the "stable" or "main" patch (usually the one on the highest version number).
3.  Compare the "stable" patch with patches for other affected versions.
    -   Use the local git submodule at `repositories/django`.
    -   Run `git show <commit_hash>` or `git diff <parent_hash> <commit_hash>` to get the patch content.
    -   Normalize the patch (ignore commit metadata like hash, author, date, and context lines if strictly checking logic).
        - A strict `git diff` comparison usually suffices if checking for exact cherry-picks.
4.  Update the `same_as_stable` field in `data.json` with `true` or `false` based on the comparison.

Data Sources:
-------------
-   Patches are referenced in official Django security announcements:
    https://docs.djangoproject.com/en/dev/releases/security/#february-3-2026-cve-2026-1207
-   The git history is available in `repositories/django`.

More instructions:
----------------------
1.  Ensure the `repositories/django` submodule is initialized and up to date.
    `git submodule update --init --recursive`
2.  Fill in the `data.json` with the commit hashes from the Django security release page.
3.  Implement the `extract_patch_content` and `compare_patches` functions below.
4.  Run this script to automatically populate/verify the `same_as_stable` field.
"""

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tqdm import tqdm


SEMVER_SERIES_RE = re.compile(r"^(\d+)\.(\d+)\.x$", re.IGNORECASE)


# -----------------------------
# Basic JSON helpers
# -----------------------------
def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, obj: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")
    tmp.replace(path)


# -----------------------------
# Git helpers
# -----------------------------
def run_git(repo_dir: Path, args: List[str], stdin: Optional[str] = None) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(repo_dir),
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"git failed: {' '.join(args)}")
    return proc.stdout


def extract_patch_content(repo_dir: Path, commit: str) -> str:
    """
    Requirement-aligned:
      - Get patch content using git show (diff only; no commit metadata)
    """
    # --pretty=format: removes commit metadata; this yields just the diff
    return run_git(repo_dir, ["show", commit, "--pretty=format:", "--no-color"])


def compare_patches(repo_dir: Path, stable_commit: str, other_commit: str) -> bool:
    """
    Requirement-aligned:
      - Normalize patch by ignoring commit metadata (handled by --pretty=format:)
      - Compare "identical patch content" using git patch-id --stable
        (this is the standard way to detect cherry-picks / identical diffs)
    Returns:
      True if identical to stable, else False
    """
    stable_diff = extract_patch_content(repo_dir, stable_commit).strip()
    other_diff = extract_patch_content(repo_dir, other_commit).strip()

    if not stable_diff or not other_diff:
        return False

    stable_pid = run_git(repo_dir, ["patch-id", "--stable"], stdin=stable_diff).split()[0]
    other_pid = run_git(repo_dir, ["patch-id", "--stable"], stdin=other_diff).split()[0]
    return stable_pid == other_pid


# -----------------------------
# Stable patch selection
# -----------------------------
def series_key(series: str) -> Tuple[int, int]:
    """
    Turns "6.0.x" into (6, 0) for comparisons.
    Unknown/non-series sorts lowest.
    """
    m = SEMVER_SERIES_RE.match((series or "").strip())
    if not m:
        return (-1, -1)
    return (int(m.group(1)), int(m.group(2)))


def choose_stable_patch_commit(entry: Dict[str, Any]) -> Optional[str]:
    """
    Requirement: stable/main patch = usually highest version number bucket.
    We use max(series_key(version)) and take the first patch commit inside it.
    """
    avs = entry.get("affected_versions") or []
    if not isinstance(avs, list) or not avs:
        return None

    # pick the affected_versions bucket with the highest version series
    best_av = max(
        (av for av in avs if isinstance(av, dict)),
        key=lambda av: series_key(av.get("version", "")),
        default=None,
    )
    if not best_av:
        return None

    patches = best_av.get("patches") or []
    if not isinstance(patches, list) or not patches:
        return None

    first = patches[0]
    if not isinstance(first, dict):
        return None
    return first.get("commit")


# -----------------------------
# Main
# -----------------------------
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Compare Django security patch commits to the stable/main patch per CVE and update same_as_stable."
    )
    ap.add_argument("--data", default="data.json", help="Path to data.json (default: data.json)")
    ap.add_argument("--repo", default="repositories/django", help="Path to django git repo (default: repositories/django)")
    args = ap.parse_args()

    data_path = Path(args.data)
    repo_dir = Path(args.repo)

    # sanity: repo is a git repo
    run_git(repo_dir, ["rev-parse", "--git-dir"])

    data = read_json(data_path)
    if not isinstance(data, list):
        raise SystemExit("[error] data.json must be a top-level JSON list")

    for entry in tqdm(data, desc="CVEs", unit="cve"):
        stable_commit = choose_stable_patch_commit(entry)
        if not stable_commit:
            # nothing to do for this CVE
            continue

        avs = entry.get("affected_versions") or []
        for av in avs:
            if not isinstance(av, dict):
                continue
            for p in av.get("patches") or []:
                if not isinstance(p, dict):
                    continue
                commit = p.get("commit")
                if not commit:
                    continue

                # identical to stable => true; else false
                try:
                    p["same_as_stable"] = compare_patches(repo_dir, stable_commit, commit)
                except Exception:
                    # if git can't resolve a commit, treat as not identical (and keep running)
                    p["same_as_stable"] = False

    write_json(data_path, data)
    print(f"[ok] Updated same_as_stable in {data_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

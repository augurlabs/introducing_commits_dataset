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
import logging
import random
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from packaging.version import Version, InvalidVersion
from tqdm import tqdm


# -----------------------------
# Logging (structured JSON)
# -----------------------------
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
        }
        for k in ("event", "cve_id", "commit", "detail"):
            if hasattr(record, k):
                payload[k] = getattr(record, k)
        return json.dumps(payload, ensure_ascii=False)


def setup_logger(log_path: Path, verbose: bool) -> logging.Logger:
    logger = logging.getLogger("patch_compare")
    logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(JsonFormatter())

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(JsonFormatter())

    logger.handlers.clear()
    logger.addHandler(ch)
    logger.addHandler(fh)
    logger.propagate = False
    return logger


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")
    tmp.replace(path)


# -----------------------------
# Git helpers
# -----------------------------
def run_git(repo_dir: Path, args: List[str]) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(repo_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"git failed: {' '.join(args)}")
    return proc.stdout


def patch_id_from_commit(repo_dir: Path, commit: str, ignore_whitespace: bool) -> str:
    """
    Compute a stable patch-id for the commit diff.
    - exact: git show <commit> --pretty=format: --no-color
    - near:  git show -w <commit> --pretty=format: --no-color   (ignore whitespace)
    Then pipe into: git patch-id --stable
    """
    show_args = ["show", commit, "--pretty=format:", "--no-color"]
    if ignore_whitespace:
        show_args.insert(1, "-w")

    diff = run_git(repo_dir, show_args)
    if not diff.strip():
        return f"EMPTY:{commit}"

    proc = subprocess.run(
        ["git", "patch-id", "--stable"],
        cwd=str(repo_dir),
        input=diff,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "git patch-id failed")

    # "<patchid> <commit>"
    line = proc.stdout.strip().splitlines()[0]
    return line.split()[0]


def safe_version_tuple(v: Optional[str]) -> Tuple[int, Version]:
    if not v:
        return (0, Version("0"))
    try:
        return (1, Version(v))
    except InvalidVersion:
        # salvage "4.2.x"
        vx = re.sub(r"\.x\b", ".0", v)
        try:
            return (1, Version(vx))
        except InvalidVersion:
            return (0, Version("0"))


def choose_stable_commit(entry: Dict[str, Any]) -> Optional[str]:
    """
    Stable = affected_versions item with highest version_not_affected (preferred),
    else highest version. Within that, first patch commit.
    """
    avs = entry.get("affected_versions") or []
    if not isinstance(avs, list) or not avs:
        return None

    def key(av: Dict[str, Any]) -> Tuple[Tuple[int, Version], Tuple[int, Version]]:
        return (safe_version_tuple(av.get("version_not_affected")), safe_version_tuple(av.get("version")))

    best = max((av for av in avs if isinstance(av, dict)), key=key, default=None)
    if not best:
        return None
    patches = best.get("patches") or []
    if not isinstance(patches, list) or not patches:
        return None
    first = patches[0] if isinstance(patches[0], dict) else None
    if not first:
        return None
    return first.get("commit")


def ensure_bool_fields(data: List[Dict[str, Any]]) -> None:
    for entry in data:
        for av in entry.get("affected_versions", []) or []:
            for p in av.get("patches", []) or []:
                v = p.get("same_as_stable", False)
                if isinstance(v, str):
                    p["same_as_stable"] = v.strip().lower() == "true"
                elif v is None:
                    p["same_as_stable"] = False
                else:
                    p["same_as_stable"] = bool(v)


def main() -> int:
    ap = argparse.ArgumentParser(description="Research-grade patch equivalence for Django CVE fixes")
    ap.add_argument("--data", default="data.json", help="Path to data.json")
    ap.add_argument("--repo", default="repositories/django", help="Path to django git repo")
    ap.add_argument("--log", default="patch_compare.log.jsonl", help="Log file path")
    ap.add_argument("--manifest", default="run_manifest_patch_compare.json", help="Run manifest path")
    ap.add_argument("--verbose", action="store_true", help="Verbose console logs")
    args = ap.parse_args()

    data_path = Path(args.data)
    repo_dir = Path(args.repo)
    log_path = Path(args.log)
    manifest_path = Path(args.manifest)

    logger = setup_logger(log_path, args.verbose)

    manifest: Dict[str, Any] = {
        "tool": "patch_comparison.py",
        "started_at": utc_now_iso(),
        "config": {"data": str(data_path), "repo": str(repo_dir)},
        "stats": {"cves_total": 0, "patches_total": 0, "exact_matches": 0, "near_matches": 0, "different": 0, "errors": 0},
        "per_cve": [],
        "errors": [],
    }

    try:
        # sanity: repo exists and is git
        run_git(repo_dir, ["rev-parse", "--git-dir"])

        data = read_json(data_path)
        if not isinstance(data, list):
            raise RuntimeError("data.json must be a top-level JSON list")

        ensure_bool_fields(data)

        manifest["stats"]["cves_total"] = len(data)

        for entry in tqdm(data, desc="CVEs", unit="cve"):
            cve_id = entry.get("cve_id", "UNKNOWN")
            stable_commit = choose_stable_commit(entry)
            if not stable_commit:
                manifest["stats"]["errors"] += 1
                manifest["errors"].append({"cve_id": cve_id, "error": "No stable commit found"})
                logger.warning("no_stable_commit", extra={"event": "no_stable_commit", "cve_id": cve_id})
                continue

            try:
                stable_pid_exact = patch_id_from_commit(repo_dir, stable_commit, ignore_whitespace=False)
                stable_pid_near = patch_id_from_commit(repo_dir, stable_commit, ignore_whitespace=True)
            except Exception as e:
                manifest["stats"]["errors"] += 1
                manifest["errors"].append({"cve_id": cve_id, "error": f"Stable patch-id failed: {e}"})
                logger.error("stable_patch_id_failed", extra={"event": "stable_patch_id_failed", "cve_id": cve_id, "commit": stable_commit, "detail": str(e)})
                continue

            avs = entry.get("affected_versions") or []
            patches_total = sum(len((av.get("patches") or [])) for av in avs if isinstance(av, dict))
            manifest["stats"]["patches_total"] += patches_total

            cve_exact = 0
            cve_near = 0
            cve_diff = 0
            cve_err = 0

            for av in avs:
                if not isinstance(av, dict):
                    continue
                for p in av.get("patches") or []:
                    if not isinstance(p, dict):
                        continue
                    commit = p.get("commit")
                    if not commit:
                        continue

                    try:
                        pid_exact = patch_id_from_commit(repo_dir, commit, ignore_whitespace=False)
                        if pid_exact == stable_pid_exact:
                            # exact match => same_as_stable = True
                            p["same_as_stable"] = True
                            cve_exact += 1
                            continue

                        # near tier: ignore whitespace
                        pid_near = patch_id_from_commit(repo_dir, commit, ignore_whitespace=True)
                        if pid_near == stable_pid_near:
                            # schema remains boolean; near match is reported in manifest only
                            p["same_as_stable"] = False
                            cve_near += 1
                        else:
                            p["same_as_stable"] = False
                            cve_diff += 1

                    except Exception as e:
                        cve_err += 1
                        manifest["stats"]["errors"] += 1
                        manifest["errors"].append({"cve_id": cve_id, "commit": commit, "error": str(e)})
                        logger.warning("patch_compare_failed", extra={"event": "patch_compare_failed", "cve_id": cve_id, "commit": commit, "detail": str(e)})

            manifest["stats"]["exact_matches"] += cve_exact
            manifest["stats"]["near_matches"] += cve_near
            manifest["stats"]["different"] += cve_diff

            manifest["per_cve"].append({
                "cve_id": cve_id,
                "stable_commit": stable_commit,
                "counts": {"exact": cve_exact, "near": cve_near, "different": cve_diff, "errors": cve_err},
            })

        # Write updated dataset
        write_json(data_path, data)

        manifest["finished_at"] = utc_now_iso()
        write_json(manifest_path, manifest)

        logger.info("run_complete", extra={"event": "run_complete"})
        return 0

    except Exception as e:
        manifest["finished_at"] = utc_now_iso()
        manifest["stats"]["errors"] += 1
        manifest["errors"].append({"error": str(e)})
        write_json(manifest_path, manifest)
        logger.error("fatal", extra={"event": "fatal", "detail": str(e)})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

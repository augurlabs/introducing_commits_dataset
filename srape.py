"""
Script Objective:
-----------------
This script is intended to help automate the population of `data.json` by scraping 
security advisory information from the official Django project website and CVE databases.

Target Data Structure:
----------------------
The output should match the schema defined in `data.json`:
- cve_id (e.g., CVE-2024-XXXX)
- cve_description (from NVD/MITRE)
- django_description (from Django security release)
- cwe (id, name)
- fixed_in (version number)
- affected_versions (list of objects with version and patches)

Data Sources:
-------------
1.  **Django Security Releases**: 
    https://docs.djangoproject.com/en/dev/releases/security/
    - This is the main archive of all security content.
    - It lists all security releases. You will need to click through to each specific release note (e.g., "Django 4.2.11 released") to find details like CVEs, descriptions, and patch links.
    
2.  **CVE Details (cve.org)**:
    https://www.cve.org
    - This is the official source for CVE Records.
    - Use this to fetch the canonical "Description" and "CWE Category" for each CVE ID found in the Django docs.
    - You can inspect the CVE content by visiting `https://www.cve.org/CVERecord?id=CVE-YYYY-XXXX`.
    - **To find the CWE ID**: Look for the "CWE" or "Weakness Enumeration" section on the CVE record page. It usually lists the CWE ID (e.g., CWE-79) and its name (e.g., Cross-site Scripting).


3.  **GitHub / Django Source**:
    - Patch links in the Django blog often point to GitHub commits.
    - We need to extract the commit hash from these URLs.

Recommended Steps for Implementation:
-------------------------------------
1.  **Fetch Security Log**:
    - Request `https://docs.djangoproject.com/en/dev/releases/security/`.
    - Parse the HTML to find links to individual security release posts.

2.  **Parse Release Post**:
    - For each release post, extract the CVE IDs mentioned.
    - Extract the description of the vulnerability.
    - Identify the versions mentioned (e.g., "Django 4.2.x", "Fixed in 5.0.1").
    - Find the patch links (look for "Apply this patch" or links to `github.com/django/django/commit/...`).
    - Map patches to specific versions if possible (often described in text like "Table of contents" or "Affected supported versions").

3.  **Enrich with CVE Data**:
    - For each extracted CVE ID, query the cve.org website or API.
    - Get the official `cve_description` and `cwe` information.

4.  **Format and Save**:
    - Construct the JSON objects.
    - Save to `data.json`.

"""

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import random
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm


BASE = "https://docs.djangoproject.com"
SECURITY_INDEX_URL = f"{BASE}/en/dev/releases/security/"

# FIX 1 (Critical): Use reliable public JSON CVE source (MITRE CVE Services)
CVE_API_URL = "https://cveawg.mitre.org/api/cve/"

# Optional fallback (coverage + reliability)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
GITHUB_COMMIT_RE = re.compile(
    r"https?://github\.com/django/django/commit/([0-9a-f]{7,40})\b", re.IGNORECASE
)
SEMVER_TAG_RE = re.compile(r"^\d+\.\d+\.\d+$")

DEFAULT_MAX_WORKERS = 6
DEFAULT_RPS = 1.0
DEFAULT_RETRIES = 4


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
        for k in ("event", "url", "cve_id", "path", "status", "detail", "commit"):
            if hasattr(record, k):
                payload[k] = getattr(record, k)
        return json.dumps(payload, ensure_ascii=False)


def setup_logger(log_path: Path, verbose: bool) -> logging.Logger:
    logger = logging.getLogger("scrape")
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


# -----------------------------
# Global rate limiter
# -----------------------------
class RateLimiter:
    def __init__(self, rps: float):
        self.rps = max(0.1, float(rps))
        self.min_interval = 1.0 / self.rps
        self._next_time = time.monotonic()

    def wait(self):
        now = time.monotonic()
        if now < self._next_time:
            time.sleep(self._next_time - now)
        jitter = random.uniform(0.0, 0.15 * self.min_interval)
        self._next_time = max(self._next_time + self.min_interval, time.monotonic()) + jitter


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


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
# HTTP + Cache
# -----------------------------
def request_with_cache(
    session: requests.Session,
    url: str,
    cache_path: Path,
    limiter: RateLimiter,
    logger: logging.Logger,
    refresh: bool,
    retries: int,
    timeout: int = 30,
) -> Tuple[str, Dict[str, Any]]:
    cache_meta_path = cache_path.with_suffix(".meta.json")

    headers: Dict[str, str] = {"User-Agent": "research-scraper/1.0"}
    cached_meta: Optional[Dict[str, Any]] = None
    cached_text: Optional[str] = None

    if cache_path.exists() and cache_meta_path.exists():
        try:
            cached_meta = read_json(cache_meta_path)
            cached_text = cache_path.read_text(encoding="utf-8")
        except Exception:
            cached_meta = None
            cached_text = None

    if cached_meta and not refresh:
        if cached_meta.get("etag"):
            headers["If-None-Match"] = cached_meta["etag"]
        if cached_meta.get("last_modified"):
            headers["If-Modified-Since"] = cached_meta["last_modified"]

    last_err: Optional[Exception] = None
    for attempt in range(1, retries + 1):
        try:
            limiter.wait()
            resp = session.get(url, headers=headers, timeout=timeout)
            status = resp.status_code

            if status == 304 and cached_text is not None and cached_meta is not None:
                cached_meta["fetched_at"] = utc_now_iso()
                write_json(cache_meta_path, cached_meta)
                return cached_text, cached_meta

            resp.raise_for_status()
            text = resp.text

            meta = {
                "fetched_at": utc_now_iso(),
                "url": url,
                "status": status,
                "etag": resp.headers.get("ETag"),
                "last_modified": resp.headers.get("Last-Modified"),
                "sha256": sha256_hex(text),
            }
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(text, encoding="utf-8")
            write_json(cache_meta_path, meta)
            logger.debug(
                "fetched",
                extra={"event": "fetched", "url": url, "status": status, "path": str(cache_path)},
            )
            return text, meta

        except Exception as e:
            last_err = e
            backoff = (2 ** (attempt - 1)) + random.uniform(0, 0.5)
            logger.warning("request_failed", extra={"event": "request_failed", "url": url, "detail": str(e)})
            if attempt < retries:
                time.sleep(backoff)

    assert last_err is not None
    raise last_err


# -----------------------------
# CVE enrichment (MITRE-first, NVD fallback)
# -----------------------------
def parse_cve_json5_containers(data: Dict[str, Any]) -> Tuple[str, str, str]:
    """
    Parse CVE JSON 5 style: containers.cna.descriptions + containers.cna.problemTypes
    Used for MITRE CVE Services endpoint.
    """
    desc = ""
    cwe_id = ""
    cwe_name = ""

    containers = data.get("containers", {}) if isinstance(data, dict) else {}
    cna = containers.get("cna", {}) if isinstance(containers, dict) else {}

    descriptions = cna.get("descriptions", [])
    if isinstance(descriptions, list) and descriptions:
        en = next((d for d in descriptions if isinstance(d, dict) and d.get("lang") == "en"), None)
        pick = en if en else descriptions[0]
        if isinstance(pick, dict):
            desc = pick.get("value", "") or ""

    problem_types = cna.get("problemTypes", [])
    if isinstance(problem_types, list) and problem_types:
        # pick the first non-empty CWE we find
        for pt in problem_types:
            if not isinstance(pt, dict):
                continue
            pdesc = pt.get("descriptions", [])
            if not isinstance(pdesc, list):
                continue
            for d in pdesc:
                if not isinstance(d, dict):
                    continue
                cid = d.get("cweId", "") or ""
                cname = d.get("description", "") or ""
                if cid:
                    cwe_id = cid
                    cwe_name = cname
                    break
            if cwe_id:
                break

    return desc, cwe_id, cwe_name


def parse_nvd(data: Dict[str, Any]) -> Tuple[str, str, str]:
    """
    Parse NVD CVE API 2.0 response.
    """
    desc = ""
    cwe_id = ""
    cwe_name = ""

    vulns = data.get("vulnerabilities", [])
    if not isinstance(vulns, list) or not vulns:
        return desc, cwe_id, cwe_name

    cve = vulns[0].get("cve", {}) if isinstance(vulns[0], dict) else {}
    descriptions = cve.get("descriptions", [])
    if isinstance(descriptions, list) and descriptions:
        en = next((d for d in descriptions if isinstance(d, dict) and d.get("lang") == "en"), None)
        pick = en if en else descriptions[0]
        if isinstance(pick, dict):
            desc = pick.get("value", "") or ""

    weaknesses = cve.get("weaknesses", [])
    if isinstance(weaknesses, list) and weaknesses:
        for w in weaknesses:
            if not isinstance(w, dict):
                continue
            wdesc = w.get("description", [])
            if not isinstance(wdesc, list):
                continue
            for d in wdesc:
                if not isinstance(d, dict):
                    continue
                value = (d.get("value", "") or "").strip()
                # Often looks like "CWE-79"
                if value.upper().startswith("CWE-"):
                    cwe_id = value.upper()
                    cwe_name = ""  # NVD often doesn't include name here
                    return desc, cwe_id, cwe_name

    return desc, cwe_id, cwe_name


def fetch_cve_enrichment(
    session: requests.Session,
    cve_id: str,
    cache_dir: Path,
    limiter: RateLimiter,
    logger: logging.Logger,
    refresh: bool,
    retries: int,
) -> Dict[str, str]:
    cve_id_u = cve_id.upper()

    # Primary: MITRE CVE Services
    mitre_url = CVE_API_URL + cve_id_u
    mitre_cache = cache_dir / "mitre" / f"{cve_id_u}.json"

    desc = ""
    cwe_id = ""
    cwe_name = ""

    try:
        text, _meta = request_with_cache(
            session=session,
            url=mitre_url,
            cache_path=mitre_cache,
            limiter=limiter,
            logger=logger,
            refresh=refresh,
            retries=retries,
            timeout=30,
        )
        data = json.loads(text)
        desc, cwe_id, cwe_name = parse_cve_json5_containers(data)
    except Exception as e:
        logger.warning(
            "cve_mitre_failed",
            extra={"event": "cve_mitre_failed", "cve_id": cve_id_u, "detail": str(e), "url": mitre_url},
        )

    # Fallback: NVD (helps fill gaps / if MITRE fails)
    if not desc or not cwe_id:
        nvd_url = NVD_API_URL + cve_id_u
        nvd_cache = cache_dir / "nvd" / f"{cve_id_u}.json"
        try:
            text, _meta = request_with_cache(
                session=session,
                url=nvd_url,
                cache_path=nvd_cache,
                limiter=limiter,
                logger=logger,
                refresh=refresh,
                retries=retries,
                timeout=30,
            )
            data = json.loads(text)
            nvd_desc, nvd_cwe_id, nvd_cwe_name = parse_nvd(data)
            if not desc:
                desc = nvd_desc
            if not cwe_id:
                cwe_id = nvd_cwe_id
            if not cwe_name:
                cwe_name = nvd_cwe_name
        except Exception as e:
            logger.warning(
                "cve_nvd_failed",
                extra={"event": "cve_nvd_failed", "cve_id": cve_id_u, "detail": str(e), "url": nvd_url},
            )

    return {"cve_description": desc or "", "cwe_id": cwe_id or "", "cwe_name": cwe_name or ""}


# -----------------------------
# Git inference module (FAST + cached)
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


def normalize_tag(tag: str) -> str:
    return tag.strip().replace("refs/tags/", "")


def semver_tuple(tag: str) -> Tuple[int, int, int]:
    a, b, c = tag.split(".")
    return (int(a), int(b), int(c))


class CommitTagInferer:
    """
    FIX 2 (Critical): Return ONE bucket per commit.
    We choose the single earliest semver tag overall that contains the commit, and derive series from it.
    This prevents 'affected_versions' explosion.
    """
    def __init__(self, repo_dir: Path, logger: logging.Logger):
        self.repo_dir = repo_dir
        self.logger = logger
        self._cache: Dict[str, List[Tuple[str, str]]] = {}

        _ = run_git(repo_dir, ["rev-parse", "--git-dir"])

    def tags_containing(self, commit: str) -> List[str]:
        out = run_git(self.repo_dir, ["tag", "--contains", commit])
        return [normalize_tag(t) for t in out.splitlines() if t.strip()]

    def infer(self, commit: str) -> List[Tuple[str, str]]:
        if commit in self._cache:
            return self._cache[commit]

        try:
            tags = self.tags_containing(commit)
        except Exception as e:
            self.logger.warning(
                "tag_contains_failed",
                extra={"event": "tag_contains_failed", "commit": commit, "detail": str(e)},
            )
            self._cache[commit] = []
            return []

        semver_tags = [t for t in tags if SEMVER_TAG_RE.match(t)]
        if not semver_tags:
            self._cache[commit] = []
            return []

        earliest = min(semver_tags, key=semver_tuple)
        major, minor, _patch = semver_tuple(earliest)
        inferred = [(f"{major}.{minor}.x", earliest)]
        self._cache[commit] = inferred
        return inferred


# -----------------------------
# Django scraping
# -----------------------------
def extract_release_links(index_html: str) -> List[str]:
    soup = BeautifulSoup(index_html, "html.parser")
    links: List[str] = []

    for a in soup.find_all("a", href=True):
        href = a["href"]
        if "/releases/security/" in href:
            links.append(urljoin(BASE, href))

    # de-dupe deterministic
    seen = set()
    out = []
    for u in links:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _dedupe_patches(patches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    uniq = []
    for p in patches:
        c = p.get("commit")
        if not c or c in seen:
            continue
        seen.add(c)
        uniq.append(p)
    return uniq


def parse_release_page(
    release_html: str,
) -> Dict[str, Tuple[str, List[Dict[str, Any]]]]:
    """
    FIX 3 (Important): Extract patches PER CVE SECTION, not "whole page for every CVE".

    Returns:
        {CVE-ID: (django_description, patches_for_that_cve)}
    """
    soup = BeautifulSoup(release_html, "html.parser")

    # Best-effort overall Django description: first paragraph
    p = soup.find("p")
    base_desc = p.get_text(" ", strip=True) if p else ""
    base_desc = re.sub(r"\s+", " ", base_desc).strip()

    # Find headers that mention a CVE, then capture content until next header.
    headers = soup.find_all(["h2", "h3", "h4"])
    sections: Dict[str, Tuple[str, List[Dict[str, Any]]]] = {}

    for h in headers:
        h_text = h.get_text(" ", strip=True)
        found = {m.group(0).upper() for m in CVE_RE.finditer(h_text)}
        if not found:
            continue

        # Collect nodes until next header
        nodes: List[Any] = []
        cur = h.next_sibling
        while cur is not None:
            if getattr(cur, "name", None) in ("h2", "h3", "h4"):
                break
            nodes.append(cur)
            cur = cur.next_sibling

        # Build section HTML fragment and parse for commits + local desc
        frag_html = "".join(str(n) for n in nodes)
        frag = BeautifulSoup(frag_html, "html.parser")

        # section description: first paragraph after header, fallback to base_desc
        p2 = frag.find("p")
        section_desc = p2.get_text(" ", strip=True) if p2 else ""
        section_desc = re.sub(r"\s+", " ", section_desc).strip() or base_desc

        patches: List[Dict[str, Any]] = []
        for a in frag.find_all("a", href=True):
            m = GITHUB_COMMIT_RE.search(a["href"])
            if m:
                commit = m.group(1)
                patches.append(
                    {
                        "commit": commit,
                        "url": f"https://github.com/django/django/commit/{commit}",
                        "same_as_stable": False,
                    }
                )
        patches = _dedupe_patches(patches)

        for cve_id in sorted(found):
            # If multiple headers mention same CVE, merge patches conservatively.
            if cve_id not in sections:
                sections[cve_id] = (section_desc, patches)
            else:
                old_desc, old_patches = sections[cve_id]
                merged = _dedupe_patches(old_patches + patches)
                # keep the first non-empty desc
                desc_to_use = old_desc or section_desc
                sections[cve_id] = (desc_to_use, merged)

    # Fallback: if no CVE headers found, do page-wide extraction as last resort
    if not sections:
        text = soup.get_text("\n")
        cves = sorted({m.group(0).upper() for m in CVE_RE.finditer(text)})

        patches: List[Dict[str, Any]] = []
        for a in soup.find_all("a", href=True):
            m = GITHUB_COMMIT_RE.search(a["href"])
            if m:
                commit = m.group(1)
                patches.append(
                    {
                        "commit": commit,
                        "url": f"https://github.com/django/django/commit/{commit}",
                        "same_as_stable": False,
                    }
                )
        patches = _dedupe_patches(patches)

        for cve_id in cves:
            sections[cve_id] = (base_desc, patches)

    return sections


def deterministic_sort_cve_id(cve_id: str) -> Tuple[int, int]:
    m = re.match(r"CVE-(\d{4})-(\d+)", cve_id.upper())
    if not m:
        return (0, 0)
    return (int(m.group(1)), int(m.group(2)))


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


def build_affected_versions_from_inference(
    patches: List[Dict[str, Any]],
    inferer: Optional[CommitTagInferer],
) -> List[Dict[str, Any]]:
    """
    Build affected_versions list by assigning each patch commit to ONE series+first-fixed-tag bucket.
    If no tag inference, fall back to a single "unknown" bucket with all patches.
    """
    if inferer is None:
        return [
            {
                "version": "unknown",
                "version_not_affected": "",
                "patches": patches,
            }
        ]

    buckets: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for p in patches:
        commit = p["commit"]
        inferred = inferer.infer(commit)

        if not inferred:
            key = ("main", "")
            if key not in buckets:
                buckets[key] = {"version": "main", "version_not_affected": "", "patches": []}
            buckets[key]["patches"].append(p)
            continue

        # inferred is now always length 1
        series_label, earliest_tag = inferred[0]
        key = (series_label, earliest_tag)
        if key not in buckets:
            buckets[key] = {"version": series_label, "version_not_affected": earliest_tag, "patches": []}
        buckets[key]["patches"].append(p)

    def sort_key(item: Dict[str, Any]) -> Tuple[int, int, int, int]:
        v = item.get("version", "")
        vna = item.get("version_not_affected", "")
        if v == "main":
            return (10**9, 10**9, 10**9, 1)
        if SEMVER_TAG_RE.match(vna):
            a, b, c = semver_tuple(vna)
            return (a, b, c, 0)
        return (10**9, 10**9, 10**9, 0)

    out = list(buckets.values())
    for av in out:
        av["patches"] = _dedupe_patches(av.get("patches", []))

    out.sort(key=sort_key)
    return out


# -----------------------------
# Main
# -----------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Research-grade Django security scraper -> data.json (with git inference)")
    ap.add_argument("--out", default="data.json", help="Output JSON file (default: data.json)")
    ap.add_argument("--cache-dir", default="cache", help="Cache directory (default: cache/)")
    ap.add_argument("--log", default="scrape.log.jsonl", help="Log file path (default: scrape.log.jsonl)")
    ap.add_argument("--manifest", default="run_manifest_scrape.json", help="Run manifest path")
    ap.add_argument("--refresh", action="store_true", help="Refresh caches (ignore conditional GET)")
    ap.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS, help="Max worker threads for CVE fetch")
    ap.add_argument("--rps", type=float, default=DEFAULT_RPS, help="Global max requests/sec across workers")
    ap.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="HTTP retries with backoff")
    ap.add_argument("--verbose", action="store_true", help="Verbose console logs")
    ap.add_argument("--repo", default="repositories/django", help="Path to django git repo for inference")
    ap.add_argument("--infer-from-git", action="store_true", help="Infer version buckets using git tags containing commits")
    args = ap.parse_args()

    out_path = Path(args.out)
    cache_dir = Path(args.cache_dir)
    log_path = Path(args.log)
    manifest_path = Path(args.manifest)

    logger = setup_logger(log_path, args.verbose)
    session = requests.Session()
    limiter = RateLimiter(args.rps)

    inferer: Optional[CommitTagInferer] = None
    if args.infer_from_git:
        try:
            inferer = CommitTagInferer(Path(args.repo), logger)
            logger.info("git_inference_enabled", extra={"event": "git_inference_enabled", "path": str(Path(args.repo))})
        except Exception as e:
            inferer = None
            logger.warning("git_inference_disabled", extra={"event": "git_inference_disabled", "detail": str(e)})

    manifest: Dict[str, Any] = {
        "tool": "scrape.py",
        "started_at": utc_now_iso(),
        "config": {
            "out": str(out_path),
            "cache_dir": str(cache_dir),
            "refresh": args.refresh,
            "max_workers": args.max_workers,
            "rps": args.rps,
            "retries": args.retries,
            "security_index_url": SECURITY_INDEX_URL,
            "cve_api_url": CVE_API_URL,
            "nvd_api_url": NVD_API_URL,
            "infer_from_git": bool(args.infer_from_git),
            "repo": str(Path(args.repo)),
        },
        "stats": {
            "release_links": 0,
            "release_pages_parsed": 0,
            "cves_found": 0,
            "cve_enriched": 0,
            "errors": 0,
        },
        "errors": [],
        "sources": {"django_index": {}, "django_pages": [], "cve_api": []},
    }

    try:
        index_cache = cache_dir / "django" / "security_index.html"
        index_html, index_meta = request_with_cache(
            session=session,
            url=SECURITY_INDEX_URL,
            cache_path=index_cache,
            limiter=limiter,
            logger=logger,
            refresh=args.refresh,
            retries=args.retries,
        )
        manifest["sources"]["django_index"] = index_meta

        links = extract_release_links(index_html)
        manifest["stats"]["release_links"] = len(links)

        cve_to_entry: Dict[str, Dict[str, Any]] = {}

        for url in tqdm(links, desc="Release pages", unit="page"):
            page_cache = cache_dir / "django" / "pages" / f"{sha256_hex(url)}.html"
            html, meta = request_with_cache(
                session=session,
                url=url,
                cache_path=page_cache,
                limiter=limiter,
                logger=logger,
                refresh=args.refresh,
                retries=args.retries,
            )
            manifest["sources"]["django_pages"].append(meta)
            manifest["stats"]["release_pages_parsed"] += 1

            per_cve = parse_release_page(html)

            for cve_id, (django_desc, patches) in per_cve.items():
                affected_versions = build_affected_versions_from_inference(patches, inferer)

                if cve_id not in cve_to_entry:
                    cve_to_entry[cve_id] = {
                        "cve_id": cve_id,
                        "cve_description": "",
                        "django_description": django_desc,
                        "cwe": {"id": "", "name": ""},
                        "affected_versions": affected_versions,
                    }
                else:
                    if (not cve_to_entry[cve_id].get("django_description")) and django_desc:
                        cve_to_entry[cve_id]["django_description"] = django_desc

                    existing = {
                        (av["version"], av.get("version_not_affected", "")): av
                        for av in cve_to_entry[cve_id].get("affected_versions", [])
                    }
                    for av in affected_versions:
                        key = (av["version"], av.get("version_not_affected", ""))
                        if key not in existing:
                            existing[key] = av
                        else:
                            merged = _dedupe_patches(existing[key].get("patches", []) + av.get("patches", []))
                            existing[key]["patches"] = merged

                    cve_to_entry[cve_id]["affected_versions"] = sorted(
                        existing.values(),
                        key=lambda x: (x["version"] == "main", x.get("version_not_affected", ""), x["version"]),
                    )

        all_cves = sorted(cve_to_entry.keys(), key=deterministic_sort_cve_id)
        manifest["stats"]["cves_found"] = len(all_cves)

        cve_cache_dir = cache_dir / "cve"
        enrichment: Dict[str, Dict[str, str]] = {}

        with ThreadPoolExecutor(max_workers=args.max_workers) as ex:
            futures = {
                ex.submit(
                    fetch_cve_enrichment,
                    session,
                    cve_id,
                    cve_cache_dir,
                    limiter,
                    logger,
                    args.refresh,
                    args.retries,
                ): cve_id
                for cve_id in all_cves
            }

            for fut in tqdm(as_completed(futures), total=len(futures), desc="CVE enrich", unit="cve"):
                cve_id = futures[fut]
                try:
                    enrichment[cve_id] = fut.result()
                    manifest["stats"]["cve_enriched"] += 1
                except Exception as e:
                    manifest["stats"]["errors"] += 1
                    manifest["errors"].append({"cve_id": cve_id, "error": str(e)})
                    logger.error(
                        "cve_enrich_failed",
                        extra={"event": "cve_enrich_failed", "cve_id": cve_id, "detail": str(e)},
                    )

        output: List[Dict[str, Any]] = []
        for cve_id in all_cves:
            entry = cve_to_entry[cve_id]
            enrich = enrichment.get(cve_id, {})
            entry["cve_description"] = enrich.get("cve_description", "") or ""
            entry["cwe"]["id"] = enrich.get("cwe_id", "") or ""
            entry["cwe"]["name"] = enrich.get("cwe_name", "") or ""
            output.append(entry)

        ensure_bool_fields(output)
        write_json(out_path, output)

        manifest["finished_at"] = utc_now_iso()
        write_json(manifest_path, manifest)

        logger.info("run_complete", extra={"event": "run_complete", "path": str(out_path)})
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

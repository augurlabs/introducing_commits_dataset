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
import json
import random
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm


# Django security archive (by default we’ll use /en/stable/ which redirects to a specific version)
DEFAULT_BASE_URL = "https://docs.djangoproject.com/en/stable/"
ARCHIVE_PATH = "releases/security/"

# CVE enrichment (MITRE CVE Services API)
MITRE_CVE_API = "https://cveawg.mitre.org/api/cve/"  # + CVE-YYYY-NNNN


# Django page often uses "CVE 2026-1207" (space) in headings/links
CVE_ANY_RE = re.compile(r"\bCVE[\s-](\d{4})[\s-](\d{4,})\b", re.IGNORECASE)

# Patch links on archive page typically point to github commit URLs
GITHUB_COMMIT_RE = re.compile(
    r"https?://github\.com/django/django/commit/([0-9a-f]{7,40})\b", re.IGNORECASE
)

# Extract something like "Django 6.0" or "Django 5.2.3" from list item text
DJANGO_VERSION_RE = re.compile(r"\bDjango\s+(\d+\.\d+(?:\.\d+)?)\b", re.IGNORECASE)


@dataclass
class RateLimiter:
    rps: float
    next_time: float = 0.0

    def __post_init__(self) -> None:
        self.rps = max(0.1, float(self.rps))
        self.next_time = time.monotonic()

    def wait(self) -> None:
        min_interval = 1.0 / self.rps
        now = time.monotonic()
        if now < self.next_time:
            time.sleep(self.next_time - now)
        # small jitter helps avoid sync bursts
        jitter = random.uniform(0.0, 0.15 * min_interval)
        self.next_time = max(self.next_time + min_interval, time.monotonic()) + jitter


def normalize_cve(text: str) -> Optional[str]:
    m = CVE_ANY_RE.search(text)
    if not m:
        return None
    year, num = m.group(1), m.group(2)
    return f"CVE-{year}-{num}"


def http_get(session: requests.Session, url: str, limiter: RateLimiter, timeout: int, retries: int) -> str:
    headers = {"User-Agent": "django-security-research-scrape/1.0"}
    last_err: Optional[Exception] = None
    for attempt in range(1, retries + 1):
        try:
            limiter.wait()
            resp = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            last_err = e
            if attempt < retries:
                backoff = (2 ** (attempt - 1)) + random.uniform(0, 0.5)
                time.sleep(backoff)
    assert last_err is not None
    raise last_err


def parse_mitre_cve(data: Dict[str, Any]) -> Tuple[str, str, str]:
    """
    Pull:
      - description (English if available)
      - cwe id + name (best-effort)
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
            desc = (pick.get("value") or "").strip()

    problem_types = cna.get("problemTypes", [])
    if isinstance(problem_types, list):
        for pt in problem_types:
            if not isinstance(pt, dict):
                continue
            pdesc = pt.get("descriptions", [])
            if not isinstance(pdesc, list):
                continue
            for d in pdesc:
                if not isinstance(d, dict):
                    continue
                cid = (d.get("cweId") or "").strip()
                cname = (d.get("description") or "").strip()
                if cid:
                    cwe_id, cwe_name = cid, cname
                    return desc, cwe_id, cwe_name

    return desc, cwe_id, cwe_name


def enrich_cve(session: requests.Session, cve_id: str, limiter: RateLimiter, timeout: int, retries: int) -> Dict[str, str]:
    url = MITRE_CVE_API + cve_id
    try:
        text = http_get(session, url, limiter=limiter, timeout=timeout, retries=retries)
        data = json.loads(text)
        desc, cwe_id, cwe_name = parse_mitre_cve(data)
        return {"cve_description": desc or "", "cwe_id": cwe_id or "", "cwe_name": cwe_name or ""}
    except Exception:
        # best-effort project: leave blank if a record is missing/unavailable
        return {"cve_description": "", "cwe_id": "", "cwe_name": ""}


def group_patches_by_series(patches: List[Tuple[str, str, str]]) -> List[Dict[str, Any]]:
    """
    patches: list of (series_label, commit, url)
    series_label example: "6.0.x" (derived from the li text)
    """
    buckets: Dict[str, Dict[str, Any]] = {}
    for series_label, commit, url in patches:
        b = buckets.setdefault(
            series_label,
            {"version": series_label, "version_not_affected": "", "patches": []},
        )
        # de-dupe commits within a bucket
        if any(p.get("commit") == commit for p in b["patches"]):
            continue
        b["patches"].append({"commit": commit, "url": url, "same_as_stable": False})

    # stable-ish ordering: sort by major/minor numbers when possible, else last
    def sort_key(v: str) -> Tuple[int, int, str]:
        m = re.match(r"^(\d+)\.(\d+)\.x$", v)
        if not m:
            return (10**9, 10**9, v)
        return (int(m.group(1)), int(m.group(2)), v)

    return [buckets[k] for k in sorted(buckets.keys(), key=sort_key)]


def parse_archive_page(archive_html: str, archive_url: str) -> Dict[str, Dict[str, Any]]:
    """
    Parse https://docs.djangoproject.com/en/<ver>/releases/security/
    into:
      cve_id -> { django_description, affected_versions[] }
    """
    soup = BeautifulSoup(archive_html, "html.parser")

    # Each issue is usually a <h3> like:
    # "February 3, 2026 - CVE 2026-1207"
    issue_headers = soup.find_all(["h3", "h2"])
    cve_map: Dict[str, Dict[str, Any]] = {}

    for h in issue_headers:
        cve_id = normalize_cve(h.get_text(" ", strip=True))
        if not cve_id:
            continue

        # Collect content until next header of same-ish level
        nodes: List[Any] = []
        cur = h.next_sibling
        while cur is not None:
            if getattr(cur, "name", None) in ("h2", "h3"):
                break
            nodes.append(cur)
            cur = cur.next_sibling

        frag = BeautifulSoup("".join(str(n) for n in nodes), "html.parser")

        # django_description: first meaningful line of text in this block
        django_desc = ""
        # Prefer a plain text sentence before the bullet list
        # (Archive page typically has a single-sentence description right after the header)
        text_lines = [ln.strip() for ln in frag.get_text("\n").splitlines()]
        text_lines = [ln for ln in text_lines if ln]
        # Filter out common boilerplate fragments
        for ln in text_lines:
            if ln.lower().startswith("django "):  # bullet intro, not the vulnerability description
                continue
            if ln.lower().startswith("full description"):
                continue
            django_desc = ln
            break

        # Patch list items: "Django 6.0 (patch)" -> commit link
        patches: List[Tuple[str, str, str]] = []
        for li in frag.find_all("li"):
            li_text = li.get_text(" ", strip=True)
            vm = DJANGO_VERSION_RE.search(li_text)
            series_label = "unknown"
            if vm:
                ver = vm.group(1)  # "6.0" or "5.2.3"
                parts = ver.split(".")
                if len(parts) >= 2:
                    series_label = f"{parts[0]}.{parts[1]}.x"

            for a in li.find_all("a", href=True):
                href = urljoin(archive_url, a["href"])
                cm = GITHUB_COMMIT_RE.search(href)
                if cm:
                    commit = cm.group(1)
                    patches.append((series_label, commit, f"https://github.com/django/django/commit/{commit}"))

        affected_versions = group_patches_by_series(patches) if patches else [
            {"version": "unknown", "version_not_affected": "", "patches": []}
        ]

        # Merge if CVE appears multiple times (rare)
        if cve_id not in cve_map:
            cve_map[cve_id] = {"django_description": django_desc, "affected_versions": affected_versions}
        else:
            if (not cve_map[cve_id].get("django_description")) and django_desc:
                cve_map[cve_id]["django_description"] = django_desc
            # merge version buckets
            existing = {av["version"]: av for av in cve_map[cve_id].get("affected_versions", [])}
            for av in affected_versions:
                v = av["version"]
                if v not in existing:
                    existing[v] = av
                else:
                    # merge patches
                    seen = {p["commit"] for p in existing[v].get("patches", [])}
                    for p in av.get("patches", []):
                        if p["commit"] not in seen:
                            existing[v]["patches"].append(p)
                            seen.add(p["commit"])
            cve_map[cve_id]["affected_versions"] = [existing[k] for k in sorted(existing.keys())]

    return cve_map


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Scrape Django security archive -> data.json (minimal, no HTML artifacts)."
    )
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Docs base URL (default: %(default)s)")
    ap.add_argument("--out", default="data.json", help="Output JSON file (default: %(default)s)")
    ap.add_argument("--max-workers", type=int, default=6, help="Threads for CVE enrichment (default: %(default)s)")
    ap.add_argument("--rps", type=float, default=1.0, help="Max requests/sec across all requests (default: %(default)s)")
    ap.add_argument("--retries", type=int, default=4, help="HTTP retries (default: %(default)s)")
    ap.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds (default: %(default)s)")
    args = ap.parse_args()

    base_url = args.base_url.rstrip("/") + "/"
    archive_url = urljoin(base_url, ARCHIVE_PATH)

    session = requests.Session()
    limiter = RateLimiter(args.rps)

    try:
        html = http_get(session, archive_url, limiter=limiter, timeout=args.timeout, retries=args.retries)
    except Exception as e:
        print(f"[error] Failed to fetch {archive_url}: {e}", file=sys.stderr)
        return 2

    cve_map = parse_archive_page(html, archive_url)

    if not cve_map:
        print(
            f"[error] No CVEs found on {archive_url}. "
            f"This page uses headings like 'CVE 2026-1207' (space) and/or 'CVE-2026-1207'.",
            file=sys.stderr,
        )
        return 2

    cve_ids = sorted(cve_map.keys(), key=lambda c: (int(c.split("-")[1]), int(c.split("-")[2])))

    # Enrich CVEs
    enrichment: Dict[str, Dict[str, str]] = {}
    with ThreadPoolExecutor(max_workers=args.max_workers) as ex:
        futs = {
            ex.submit(enrich_cve, session, cve_id, limiter, args.timeout, args.retries): cve_id
            for cve_id in cve_ids
        }
        for fut in tqdm(as_completed(futs), total=len(futs), desc="CVE enrich", unit="cve"):
            cve_id = futs[fut]
            enrichment[cve_id] = fut.result()

    # Build output schema
    output: List[Dict[str, Any]] = []
    for cve_id in cve_ids:
        info = cve_map[cve_id]
        enrich = enrichment.get(cve_id, {})
        output.append(
            {
                "cve_id": cve_id,
                "cve_description": enrich.get("cve_description", "") or "",
                "django_description": info.get("django_description", "") or "",
                "cwe": {
                    "id": enrich.get("cwe_id", "") or "",
                    "name": enrich.get("cwe_name", "") or "",
                },
                "affected_versions": info.get("affected_versions", []) or [],
            }
        )

    # Write file
    try:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
            f.write("\n")
    except Exception as e:
        print(f"[error] Failed to write {args.out}: {e}", file=sys.stderr)
        return 2

    print(f"[ok] Wrote {len(output)} CVEs to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

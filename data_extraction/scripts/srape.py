import json
import requests
from bs4 import BeautifulSoup
import re
import subprocess
import os
import logging
import sys
import time

# Configure logging
log_file = "../logs/scrape.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(log_file, mode='w'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

BLOG_CACHE = {}
GHSA_CACHE = {}

def fetch_all_django_ghsas():
    logger.info("Fetching all Django GHSA advisories...")
    base_url = "https://api.github.com/advisories?affects=django&type=reviewed&per_page=100"
    url = base_url
    while url:
        try:
            headers = {"Accept": "application/vnd.github.v3+json"}
            response = requests.get(url, headers=headers, timeout=20)
            if response.status_code == 200:
                advisories = response.json()
                for adv in advisories:
                    cve_id = adv.get('cve_id')
                    if cve_id:
                        GHSA_CACHE[cve_id] = adv
                url = response.links.get('next', {}).get('url')
                if url: time.sleep(1)
            else: break
        except: break
    logger.info(f"Cached {len(GHSA_CACHE)} unique Django CVEs from GitHub.")

def get_mitre_data(cve_id):
    api_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        response = requests.get(api_url, timeout=15)
        if response.status_code == 200: return response.json()
    except: pass
    return None

def get_detailed_django_description(url, cve_id):
    if not url or not url.startswith("http"): return ""
    base_url = url.split("#")[0]
    if base_url not in BLOG_CACHE:
        try:
            resp = requests.get(base_url, timeout=15)
            if resp.status_code == 200:
                BLOG_CACHE[base_url] = BeautifulSoup(resp.content, 'html.parser')
        except: return ""
    soup = BLOG_CACHE.get(base_url)
    if not soup: return ""
    header = soup.find(lambda tag: tag.name in ['h2', 'h3', 'h4'] and cve_id in tag.get_text())
    if not header:
        header = soup.find(string=re.compile(re.escape(cve_id)))
        if header: header = header.parent
    if header:
        content = []
        sibling = header.find_next_sibling()
        while sibling and sibling.name not in ['h2', 'h3', 'h4']:
            if sibling.name == 'p': content.append(sibling.get_text().strip())
            sibling = sibling.find_next_sibling()
        return " ".join(content)
    return ""

def scrape_security_archive():
    url = "https://docs.djangoproject.com/en/dev/releases/security/"
    try:
        resp = requests.get(url, timeout=20)
        soup = BeautifulSoup(resp.content, 'html.parser')
        entries = []
        headers = soup.find_all(['h2', 'h3'])
        for header in headers:
            text = header.get_text().strip()
            cve_match = re.search(r'(CVE\s*-?\s*\d{4}-\d{4,5})', text)
            if cve_match:
                cve_id = cve_match.group(1).replace(" ", "-").replace("--", "-")
                blog_url = ""
                description_summary = ""
                patches = []
                sibling = header.find_next_sibling()
                while sibling and sibling.name not in ['h2', 'h3']:
                    if sibling.name == 'p':
                        full_desc_link = sibling.find('a', string=re.compile(r'Full description|weblog'))
                        if full_desc_link:
                            blog_url = full_desc_link['href']
                            if blog_url.startswith('/'):
                                blog_url = "https://docs.djangoproject.com" + blog_url
                        if not description_summary:
                            description_summary = sibling.get_text().strip().split("Full description")[0].strip()
                    links = sibling.find_all('a', href=re.compile(r'github\.com/django/django/commit/'))
                    for link in links:
                        commit = link['href'].split('/')[-1]
                        version_text = link.parent.get_text().split('(')[0].strip() if link.parent else "Unknown"
                        patches.append({
                            "version": version_text,
                            "commit": commit,
                            "url": link['href']
                        })
                    sibling = sibling.find_next_sibling()
                entries.append({
                    "cve_id": cve_id,
                    "summary": description_summary,
                    "blog_url": blog_url,
                    "patches": patches
                })
        return entries
    except Exception as e:
        logger.error(f"Archive scrape failed: {e}")
        return []

def main():
    data_file = "../data/original_full_datatest.jsonl"
    fetch_all_django_ghsas()
    archive_entries = scrape_security_archive()
    logger.info(f"Found {len(archive_entries)} CVEs in Django archive.")
    
    existing_data = {}
    if os.path.exists(data_file):
        with open(data_file, "r") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    cid = item.get("cve", {}).get("id") or item.get("cve_id")
                    if cid: existing_data[cid] = item

    for i, entry in enumerate(archive_entries):
        cve_id = entry["cve_id"]
        logger.info(f"[{i+1}/{len(archive_entries)}] Processing {cve_id}...")
        
        robust_desc = get_detailed_django_description(entry["blog_url"], cve_id)
        ghsa = GHSA_CACHE.get(cve_id, {})
        mitre_json = get_mitre_data(cve_id) or {}
        cna = mitre_json.get('containers', {}).get('cna', {})
        
        # CWE Extraction
        cwe = {"id": None, "name": ""}
        ghsa_cwes = ghsa.get('cwes', [])
        if ghsa_cwes:
            cwe["id"] = ghsa_cwes[0].get('cwe_id')
            cwe["name"] = ghsa_cwes[0].get('name', "")
        else:
            for pt in cna.get('problemTypes', []):
                for d in pt.get('descriptions', []):
                    if d.get('lang') == 'en' and d.get('type') == 'CWE':
                        cwe["id"] = d.get('cweId')
                        cwe["name"] = d.get('description', "")
                        break
                if cwe["id"]: break

        # CVSS Extraction
        cvss = {"score": None, "vector": "", "severity": ""}
        ghsa_cvss = ghsa.get('cvss', {})
        if ghsa_cvss and ghsa_cvss.get('score'):
            cvss["score"] = ghsa_cvss.get('score')
            cvss["vector"] = ghsa_cvss.get('vector_string')
            cvss["severity"] = ghsa.get('severity', "").capitalize()
        else:
            for metric in cna.get('metrics', []):
                for ver in ['cvssV3_1', 'cvssV3_0', 'cvssV2_0']:
                    m = metric.get(ver)
                    if m:
                        cvss["score"] = m.get('baseScore')
                        cvss["vector"] = m.get('vectorString', "")
                        cvss["severity"] = m.get('baseSeverity', "")
                        break
                if cvss["score"]: break

        # GHSA Vulnerable Ranges
        vulnerable_ranges = []
        for v in ghsa.get('vulnerabilities', []):
            vulnerable_ranges.append({
                "range": v.get('vulnerable_version_range'),
                "fixed_in": v.get('first_patched_version')
            })

        # Build Nested Record
        record = {
            "cve": {
                "id": cve_id,
                "url": f"https://www.cve.org/CVERecord?id={cve_id}",
                "description": next((d.get('value') for d in cna.get('descriptions', []) if d.get('lang') == 'en'), ""),
                "published_at": mitre_json.get('cveMetadata', {}).get('datePublished'),
                "updated_at": mitre_json.get('cveMetadata', {}).get('dateUpdated')
            },
            "ghsa": {
                "id": ghsa.get('ghsa_id'),
                "url": ghsa.get('html_url'),
                "summary": ghsa.get('summary'),
                "description": ghsa.get('description'),
                "severity": (ghsa.get('severity') or cvss.get('severity') or "Unknown").capitalize(),
                "cvss": cvss,
                "vulnerable_ranges": vulnerable_ranges,
                "published_at": ghsa.get('published_at'),
                "updated_at": ghsa.get('updated_at')
            },
            "cwe": cwe,
            "django": {
                "url": entry["blog_url"],
                "description": robust_desc if robust_desc else entry["summary"],
                "fixed_versions": []
            },
            "references": sorted(list(set(
                ([ref for ref in ghsa.get('references', []) if isinstance(ref, str)]) + 
                ([ref.get('url') for ref in cna.get('references', []) if isinstance(ref, dict) and ref.get('url')]) +
                ([entry["blog_url"]] if entry["blog_url"] else [])
            )))
        }

        for p in entry["patches"]:
            record["django"]["fixed_versions"].append({
                "version": p["version"],
                "patch": {
                    "commit": p["commit"],
                    "url": p["url"]
                }
            })

        existing_data[cve_id] = record
        if (i+1) % 10 == 0:
            with open(data_file, "w") as f:
                for cid in sorted(existing_data.keys()):
                    f.write(json.dumps(existing_data[cid]) + "\n")
            time.sleep(0.5)

    with open(data_file, "w") as f:
        for cid in sorted(existing_data.keys()):
            f.write(json.dumps(existing_data[cid]) + "\n")
    logger.info("Done.")

if __name__ == "__main__":
    main()

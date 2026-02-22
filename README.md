# README (only for scrape.py and patch_comparison.py)

## Code created with assistance from ChatGPT 5.2

## Running the Scripts

---

## 1. Run the Scraper (`scrape.py`)

Basic run:

    python scrape.py

Recommended run (uses Django repo to infer correct versions for patches):

    python scrape.py --infer-from-git --repo repositories/django

Force fresh downloads (ignore cache):

    python scrape.py --refresh

Limit request speed (avoid rate limiting):

    python scrape.py --rps 0.5

Increase parallel CVE API requests:

    python scrape.py --max-workers 8


### Useful Flags for scrape.py

--infer-from-git  
    Assign patches to correct Django versions using git history

--repo PATH  
    Path to local Django repository

--refresh  
    Ignore cache and re-fetch everything

--max-workers N  
    Number of parallel CVE API workers

--rps FLOAT  
    Max HTTP requests per second

--retries N  
    Retry attempts for failed requests

--out FILE  
    Output JSON filename

--cache-dir DIR  
    Cache directory

--log FILE  
    Log file location

--manifest FILE  
    Manifest output file

--verbose  
    Enable debug logging


If using git inference, make sure Django repo exists locally:

    git submodule update --init --recursive


---

## 2. Run Patch Comparison (`patch_comparison.py`)

Basic run:

    python patch_comparison.py --data data.json --repo repositories/django

Verbose run:

    python patch_comparison.py --verbose


### Useful Flags for patch_comparison.py

--data FILE  
    Dataset JSON file

--repo PATH  
    Django git repository path

--log FILE  
    Log output file

--manifest FILE  
    Manifest output file

--verbose  
    Debug logging


---

## Typical Usage Order

Run scraper first:

    python scrape.py --infer-from-git

Then run patch comparison:

    python patch_comparison.py


---

## Dependencies (install once)

    pip install requests beautifulsoup4 tqdm packaging


---

## Full Recommended Order of Running

    git submodule update --init --recursive
    python3 scrape.py --infer-from-git --repo repositories/django
    python3 patch_comparison.py --data data.json --repo repositories/django

## Rereun when needed

    1. Update Django git repo

    cd repositories/django
    git fetch --tags --prune
    git pull --ff-only
    cd ../..

    2. Decide whether to reuse cache or force fresh data

        A. Force a fully fresh run

        rm -rf cache

        B. Keep cache but force re-download

        python3 scrape.py --refresh --infer-from-git --repo repositories/django

## Save Prior Runs

    mkdir -p runs/$(date +%Y-%m-%d)
    cp data.json run_manifest_scrape.json scrape.log.jsonl runs/$(date +%Y-%m-%d)/

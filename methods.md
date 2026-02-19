## 1. Phase 1: Search Space Discovery
**Goal:** Define the temporal bounds and validate patch consistency across version branches.

### 1.1 Metadata Extraction (Case: CVE-2025-13473)
| Data Point | Technical Value | Automated Acquisition Command |
| :--- | :--- | :--- |
| **CVE ID** | CVE-2025-13473 | Scrape CVE/NVD |
| **BFC Hash** | `3eb814e02a` | `git log --all --grep="CVE-2025-13473" --format="%H"` |
| **Patch Date** | 2025-11-19 | `git show -s --format=%ci 3eb814e02a` |
| **Stable Branches** | 4.2.x, 5.2.x, 6.0.x | `git branch -a --contains 3eb814e02a` |

### 1.2 Automated Patch Consistency Script
You must ensure the fix logic is identical across versions to consolidate your investigation.

```python
# patch_consistency_checker.py
import subprocess, os

def get_clean_diff(repo_path, commit_hash, file_path):
    # unified=0 removes context; only shows raw additions (+) and removals (-)
    cmd = ["git", "-C", repo_path, "show", "--unified=0", commit_hash, "--", file_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    # Filter metadata, keep only code logic
    return "
".join([l.strip() for l in result.stdout.splitlines() 
                     if (l.startswith('+') or l.startswith('-')) and not l.startswith(('+++','---'))])

def verify_branches(repo, file_path, commits):
    baseline = get_clean_diff(repo, commits[0], file_path)
    for c in commits:
        diff = get_clean_diff(repo, c, file_path)
        status = "MATCH" if diff == baseline else "MISMATCH"
        print(f"Commit {c[:8]}: {status}")

# Execution:
verify_branches("../django", "django/contrib/auth/handlers/modwsgi.py", 
                ["3eb814e02a", "d72cc3be3b", "184e38ab0a"])
```

---

## 2. Phase 2: Logic & Data-Flow Analysis
**Goal:** Identify the "Sink" (failure) and "Guard" (fix) to anchor the SZZ trace.

### 2.1 The Forensic "Branch vs. Burden" Thinking Process
1.  **Burden:** Password hashing (`check_password`) is slow.
2.  **Short-Circuit:** `UserModel.DoesNotExist` exception block.
3.  **Vulnerability:** The code returns `None` immediately (Short-Circuit) without performing the hashing (Burden).
4.  **Information Leak:** Attacker measures the time. Fast = No User. Slow = User exists.

### 2.2 The "Sink" Identification
In this case, the **Sink** is the logical path that lacks the "Expensive Burden."
*   **Vulnerable File:** `django/contrib/auth/handlers/modwsgi.py`
*   **Sink Line:** `except UserModel.DoesNotExist: return None`
*   **Guard Logic:** `UserModel().set_password("")` (Added to force hashing on the early return path).

### 2.3 Finding the Introducing Commit (The Backwards Trace)
To find the commit that introduced the vulnerability (BIC), trace the origin of the "Sink" logic.

1. **Identify the Sink Code:** In `modwsgi.py`, the sink is the early return in the `except UserModel.DoesNotExist` block.
2. **Execute Blame:** Run `git blame` on the vulnerable file to identify the commit for that specific line.
   ```bash
   git blame -L 20,25 django/contrib/auth/handlers/modwsgi.py
   ```
3. **Verify the "Birth" vs. "Refactor":**
   - If the commit only changed imports or whitespace, it's a **Refactor**. Blame the parent of that commit.
   - If the commit introduced the `check_password` function or the `except` block, it is the **Candidate BIC**.
4. **Contextual Analysis:** Check if the commit was a backport or a refactor of existing code from another file (e.g., standard auth views).

---

## 3. Phase 3: Verification Synthesis (The Probe)
**Goal:** Create a "Forensic Probe"—a standalone script that runs on any version of the project.

### 3.1 The Universal Forensic Probe
This script must include "Era Patches" to bypass Python version discrepancies (e.g., Python 3.12 running code from 2012).

```python
# repro_probe_cve_2025_13473.py
import sys, os, inspect, threading, html.parser
from unittest import mock

# --- ERA COMPATIBILITY LAYER ---
# Fixes 'Bit-Rot' errors when running 2012 code on Python 3.11+
if not hasattr(html.parser, 'HTMLParseError'):
    class HTMLParseError(Exception): pass
    html.parser.HTMLParseError = HTMLParseError
if not hasattr(threading, '_Event'): threading._Event = threading.Event
if not hasattr(inspect, 'getargspec'): inspect.getargspec = inspect.getfullargspec

# --- ENVIRONMENT SETUP ---
django_path = os.path.abspath("../django")
sys.path.insert(0, django_path)
from django.conf import settings
if not settings.configured:
    settings.configure(SECRET_KEY='forensics', 
                       DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3'}})

# --- PROBE LOGIC ---
def run_forensic_test():
    import django.contrib.auth.hashers
    # Mock the hasher to detect if the 'Burden' was applied
    with mock.patch('django.contrib.auth.hashers.check_password') as mock_hasher:
        from django.contrib.auth.handlers.modwsgi import check_password
        from django.contrib.auth.models import User
        
        # Trigger: Missing User
        with mock.patch.object(User.objects, 'get') as mock_get:
            mock_get.side_effect = User.DoesNotExist
            
            check_password({}, 'nonexistent_user', 'password')
            
            # Oracle Assertion
            if mock_hasher.call_count == 0:
                print("VERDICT: VULNERABLE")
                sys.exit(1) # Fail for automation
            else:
                print("VERDICT: SAFE")
                sys.exit(0)

if __name__ == "__main__":
    run_forensic_test()
```

---

## 4. Phase 4: Forensic Environment (The Switcher)
**Goal:** Automate the movement between project eras using Docker containers.

### 4.1 The Era Mapping Logic
| Project Era | Python Version | Docker Base Image |
| :--- | :--- | :--- |
| **2005 - 2013** | 2.7 | `python:2.7-slim-stretch` |
| **2014 - 2018** | 3.5 | `python:3.5-slim-jessie` |
| **2019 - Present** | 3.11+ | `python:3.11-slim-bookworm` |

### 4.2 The Automated Environment Switcher Script
This bash script determines the environment based on commit metadata.

```bash
#!/bin/bash
# era_switcher.sh
COMMIT=$1
PROBE=$2

# 1. Get Commit Date
YEAR=$(git show -s --format=%ci $COMMIT | cut -d'-' -f1)

# 2. Select Docker Image
if [ "$YEAR" -lt 2014 ]; then
    IMG="python:2.7-slim"
else
    IMG="python:3.11-slim"
fi

# 3. Execute Hermetic Test
# Mount current dir to /app, run probe inside container
docker run --rm -v $(pwd):/app -w /app $IMG 
    /bin/bash -c "pip install mock==2.0.0; python $PROBE"
```

---

## 5. Phase 5: The Sandwich Verification
**Goal:** Execute the trace and prove the BIC deterministically.

### 5.1 Verification Commands and Results
| Step | Action | Expected Output | Meaning |
| :--- | :--- | :--- | :--- |
| **1. Point C** | `git checkout 3eb814e02a` | `VERDICT: SAFE` | Fix is verified working. |
| **2. Trace** | `git blame modwsgi.py` | `373932fa6b9` | Candidate BIC identified. |
| **3. Point B** | `git checkout 373932fa6b` | `VERDICT: VULNERABLE` | Vulnerability exists in BIC. |
| **4. Point A** | `git checkout 373932fa6b^` | `ModuleNotFoundError` | Feature didn't exist (Birth). |

### 5.2 The Deterministic Verdict
The investigation proves **Commit `373932fa6b`** is the BIC because:
*   Its parent (**A**) does not contain the logic.
*   The commit itself (**B**) fails the probe.
*   The fix commit (**C**) passes the probe.

---

## 6. SZZ Improvement & Scaling
### 6.1 Hybrid SZZ Logic
Traditional SZZ fails when code is moved or refactored. Use this logic to filter candidates:
1.  **Structural SZZ:** If `git blame` points to a commit, check the file list. If >50 files changed, it is a **Refactor Candidate**.
2.  **Parent Blaming:** If a commit is a refactor, blame its parent until you find a **Functional Logic Change**.
3.  **Cross-Check:** Compare the "Functional BIC" against your **Phase 2 Logic Analysis**. If they match, prioritize this commit for the **Sandwich Run**.

### 6.2 Truth Database Schema
Store results in a JSON format for research evaluation:
```json
{
  "cve": "CVE-2025-13473",
  "bfc": "3eb814e02a",
  "bic": "373932fa6b",
  "verified": true,
  "sandwich": {"A": "Missing", "B": "Vulnerable", "C": "Fixed"},
  "cwe": "CWE-208",
  "probe_path": "probes/repro_cve_2025_13473.py"
}
```

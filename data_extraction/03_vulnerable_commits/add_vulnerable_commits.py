import subprocess
import json
import re
import os
import sys

def run_command(cmd, cwd=None):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=cwd)
        if result.returncode != 0:
            return None
        return result.stdout.strip()
    except Exception as e:
        return None

def is_refactor_commit(msg):
    # Heuristic for refactor/formatting commits
    noise_keywords = ["black", "reformat", "refactor", "lint", "flake8", "isort", "prettier", "whitespace"]
    msg_lower = msg.lower()
    return any(kw in msg_lower for kw in noise_keywords)

def is_security_fix(msg):
    # Heuristic for security fix commits
    sec_keywords = ["cve-", "security fix", "vulnerability", "fixed issue in the auth system", "security releases"]
    msg_lower = msg.lower()
    return any(kw in msg_lower for kw in sec_keywords)

def get_patch_files(repo_path, commit_hash):
    # Get files changed in the commit, ignoring tests, docs, and translations
    cmd = f"git show {commit_hash} --name-only --format="
    output = run_command(cmd, repo_path)
    if not output:
        return []
    files = output.split('\n')
    ignore_prefixes = ['tests/', 'docs/', 'django/conf/locale/', 'django/contrib/admin/locale/']
    return [f for f in files if f and not any(f.startswith(p) for p in ignore_prefixes)]

def find_vulnerable_lines(repo_path, commit_hash, file_path):
    cmd = f"git show {commit_hash} -- \"{file_path}\""
    diff = run_command(cmd, repo_path)
    if not diff:
        return []

    vulnerable_lines = []
    current_line_num = 0
    lines = diff.split('\n')
    for line in lines:
        if line.startswith('@@'):
            match = re.search(r'@@ -(\d+),(\d+) \+(\d+),(\d+) @@', line)
            if match:
                current_line_num = int(match.group(1))
        elif line.startswith('-') and not line.startswith('---'):
            # Only consider non-empty lines and non-comment-only lines
            stripped = line[1:].strip()
            if len(stripped) > 3 and not stripped.startswith('#'):
                vulnerable_lines.append((current_line_num, stripped))
            current_line_num += 1
        elif line.startswith(' '):
            current_line_num += 1
            
    return vulnerable_lines

def trace_origin(repo_path, commit_hash, file_path, line_num, content):
    current_commit = commit_hash
    current_file = file_path
    current_line = line_num
    
    # Try to go back through refactors up to 5 times
    for _ in range(5):
        parent = f"{current_commit}^"
        # Blame with movement detection
        cmd = f'git blame -w -C -C -L {current_line},{current_line} {parent} -- \"{current_file}\"'
        output = run_command(cmd, repo_path)
        
        if not output:
            break
            
        match = re.match(r'^([a-f0-9]+) (?:(\S+) )?\(.* (\d+)\)', output)
        if not match:
            break
            
        found_commit = match.group(1)
        found_file = match.group(2) if match.group(2) else current_file
        found_line = int(match.group(3))
        
        # Get commit message to check if it's a refactor
        msg_cmd = f'git show -s --format="%s" {found_commit}'
        msg = run_command(msg_cmd, repo_path)
        
        if msg and is_refactor_commit(msg):
            # It's a refactor, keep going from the parent of this commit
            current_commit = found_commit
            current_file = found_file
            current_line = found_line
            continue
        else:
            # Not a refactor, this is our origin candidate
            date_cmd = f'git show -s --format="%ai" {found_commit}'
            date = run_command(date_cmd, repo_path)
            return {
                "commit": found_commit,
                "date": date,
                "message": msg,
                "file": found_file,
                "line_content": content,
                "is_security_fix": is_security_fix(msg) if msg else False
            }
            
    return None

def process_record(record, repo_base_path):
    repo_path = os.path.join(repo_base_path, "django")
    
    if 'django' not in record or 'fixed_versions' not in record['django'] or not record['django']['fixed_versions']:
        return record

    # Use the first fixed version (often the most representative for the fix)
    patch = record['django']['fixed_versions'][0]['patch']
    patch_commit = patch['commit']
    
    files = get_patch_files(repo_path, patch_commit)
    origins = []
    
    for f in files:
        vuln_lines = find_vulnerable_lines(repo_path, patch_commit, f)
        # Trace up to 3 core lines per file to find convergence
        for line_num, content in vuln_lines[:3]:
            origin = trace_origin(repo_path, patch_commit, f, line_num, content)
            if origin and not any(o['commit'] == origin['commit'] for o in origins):
                origins.append(origin)
    
    # Heuristic: Sieve out the most relevant origin
    # If we have multiple, prioritize non-security fixes (the root) or the earliest one
    if origins:
        # Sort by date
        origins.sort(key=lambda x: x['date'])
        
        record['vulnerability_origin'] = {
            "root_introduction": origins[0],  # The earliest logical appearance
            "all_potential_origins": origins
        }
    else:
        # If no deleted lines (addition only), at least document file creation
        file_origins = []
        for f in files[:2]: # Check first two modified files
            cmd = f'git log --diff-filter=A --format="%H|%ai|%s" -- "{f}"'
            output = run_command(cmd, repo_path)
            if output:
                output_lines = output.split('\n')
                if output_lines:
                    parts = output_lines[-1].split('|')
                    if len(parts) >= 3:
                        file_origins.append({
                            "file": f,
                            "commit": parts[0],
                            "date": parts[1],
                            "message": parts[2]
                        })
        if file_origins:
            record['vulnerability_origin'] = {
                "file_creations": file_origins
            }

    return record

if __name__ == "__main__":
    input_path = "data_extraction/02_add_python_versions/data/dataset_with_py_versions.jsonl"
    output_path = "data_extraction/03_first_vulnerable_commit/data/vulnerable_commits_datatest.jsonl"
    repo_base = "repositories"
    
    with open(input_path, 'r') as f_in, open(output_path, 'w') as f_out:
        lines = f_in.readlines()
        for i, line in enumerate(lines):
            record = json.loads(line)
            sys.stdout.write(f"\rProcessing record {i+1}/{len(lines)}: {record['cve']['id']}...")
            sys.stdout.flush()
            
            processed = process_record(record, repo_base)
            f_out.write(json.dumps(processed) + '\n')
    print("\nProcessing complete.")

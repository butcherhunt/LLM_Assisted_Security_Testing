import os
import json
import glob
import shutil
import subprocess
from datetime import datetime
from typing import Optional, Dict, Any

import requests
from dotenv import load_dotenv
from fastmcp import FastMCP

load_dotenv()

# ----------------------------
# Config
# ----------------------------
MOBSF_URL = os.getenv("MOBSF_URL", "http://127.0.0.1:8001")
MOBSF_API_KEY = os.getenv("MOBSF_API_KEY", "")

ZAP_URL = os.getenv("ZAP_URL", "http://127.0.0.1:8090")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2:7b")

BASE_SCAN_DIR = os.getenv("BASE_SCAN_DIR", os.path.expanduser("~/Automated_LLM_Scan"))
ALLOWED_BASE = os.path.abspath(BASE_SCAN_DIR)
SOURCE_CODE_BASE_DIR = os.path.join(BASE_SCAN_DIR, "source_code")

# Source code / AppSec folders
SAST_RAW_DIR = os.path.join(BASE_SCAN_DIR, "SAST", "raw")
SCA_RAW_DIR = os.path.join(BASE_SCAN_DIR, "SCA", "raw")
SECRETS_RAW_DIR = os.path.join(BASE_SCAN_DIR, "Secrets", "raw")

SAST_REPORTS_DIR = os.path.join(BASE_SCAN_DIR, "SAST", "reports")
SCA_REPORTS_DIR = os.path.join(BASE_SCAN_DIR, "SCA", "reports")
SECRETS_REPORTS_DIR = os.path.join(BASE_SCAN_DIR, "Secrets", "reports")

# Mobile folders
MOBILE_BASE_DIR = os.path.join(BASE_SCAN_DIR, "Mobile_Assessment")
MOBILE_MCP_WORK_DIR = os.path.join(MOBILE_BASE_DIR, "mcp-work")
MOBILE_RAW_DIR = os.path.join(MOBILE_BASE_DIR, "raw")
MOBILE_REPORTS_DIR = os.path.join(MOBILE_BASE_DIR, "reports")

# DAST folders
DAST_BASE_DIR = os.path.join(BASE_SCAN_DIR, "DAST")
ZAP_RESULTS_DIR = os.path.join(DAST_BASE_DIR, "zap-results")
DAST_REPORTS_DIR = os.path.join(DAST_BASE_DIR, "reports")

# Consolidated folders
CONSOLIDATED_DIR = os.path.join(BASE_SCAN_DIR, "consolidated")
CONSOLIDATED_REPORTS_DIR = os.path.join(CONSOLIDATED_DIR, "reports")
DASHBOARD_EXPORT_DIR = os.path.join(BASE_SCAN_DIR, "dashboard_export")

# Jobs
JOBS_DIR = os.path.join(BASE_SCAN_DIR, "jobs")

for d in [
    BASE_SCAN_DIR,
    SOURCE_CODE_BASE_DIR,
    CONSOLIDATED_DIR,
    CONSOLIDATED_REPORTS_DIR,
    DASHBOARD_EXPORT_DIR,
    JOBS_DIR,
    SAST_RAW_DIR,
    SCA_RAW_DIR,
    SECRETS_RAW_DIR,
    SAST_REPORTS_DIR,
    SCA_REPORTS_DIR,
    SECRETS_REPORTS_DIR,
    MOBILE_MCP_WORK_DIR,
    MOBILE_RAW_DIR,
    MOBILE_REPORTS_DIR,
    ZAP_RESULTS_DIR,
    DAST_REPORTS_DIR,
]:
    os.makedirs(d, exist_ok=True)

mcp = FastMCP("security-tools")


# ----------------------------
# Helpers
# ----------------------------
def _generate_finding_id(prefix: str, counter: int) -> str:
    return f"{prefix}-{str(counter).zfill(3)}"


def _safe_path(p: str) -> str:
    """Allow access only under BASE_SCAN_DIR."""
    p = os.path.abspath(p)
    if not p.startswith(ALLOWED_BASE + os.sep) and p != ALLOWED_BASE:
        raise ValueError(f"Path not allowed. Only {ALLOWED_BASE} is permitted.")
    return p


def _safe_repo_path(p: str) -> str:
    """Allow repo operations only under BASE_SCAN_DIR/source_code."""
    p = os.path.abspath(p)
    base = os.path.abspath(SOURCE_CODE_BASE_DIR)
    if not p.startswith(base + os.sep) and p != base:
        raise ValueError(f"Repo path not allowed. Only {base} is permitted.")
    return p


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def _latest_file(folder: str, pattern: str) -> Optional[str]:
    files = glob.glob(os.path.join(folder, pattern))
    if not files:
        return None
    return max(files, key=os.path.getmtime)


def _read_text_file(path: str, max_len: int = 20000) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    if len(content) > max_len:
        content = content[:max_len] + "\n...<truncated>..."
    return content


def _run_command(cmd: list[str], cwd: Optional[str] = None) -> Dict[str, Any]:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    return {
        "success": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": proc.stdout[:5000],
        "stderr": proc.stderr[:5000],
        "command": " ".join(cmd),
    }


def _zap_params(extra: Optional[dict] = None) -> dict:
    params = {}
    if ZAP_API_KEY:
        params["apikey"] = ZAP_API_KEY
    if extra:
        params.update(extra)
    return params


def _write_json(path: str, data: Any) -> str:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path


def _repo_dest(repo_name: str) -> str:
    safe_name = repo_name.strip().replace(" ", "_")
    if not safe_name:
        raise ValueError("repo_name cannot be empty")
    return os.path.join(SOURCE_CODE_BASE_DIR, safe_name)


def _detect_platform(repo_url: str) -> str:
    url = repo_url.lower()
    if "github.com" in url:
        return "github"
    if "gitlab.com" in url or "gitlab" in url:
        return "gitlab"
    return "unknown"


def _validate_github_token(token: str) -> Dict[str, Any]:
    try:
        resp = requests.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
            },
            timeout=10,
        )
        if resp.status_code == 200:
            user_data = resp.json()
            scopes = resp.headers.get("X-OAuth-Scopes", "")
            return {
                "valid": True,
                "platform": "github",
                "username": user_data.get("login", ""),
                "name": user_data.get("name", ""),
                "scopes": scopes,
                "error": None,
            }
        if resp.status_code == 401:
            return {"valid": False, "platform": "github", "error": "Invalid or expired GitHub token."}
        return {"valid": False, "platform": "github", "error": f"GitHub API returned status {resp.status_code}"}
    except requests.RequestException as e:
        return {"valid": False, "platform": "github", "error": f"Could not reach GitHub API: {str(e)}"}


def _validate_gitlab_token(token: str) -> Dict[str, Any]:
    try:
        resp = requests.get(
            "https://gitlab.com/api/v4/user",
            headers={"PRIVATE-TOKEN": token},
            timeout=10,
        )
        if resp.status_code == 200:
            user_data = resp.json()
            return {
                "valid": True,
                "platform": "gitlab",
                "username": user_data.get("username", ""),
                "name": user_data.get("name", ""),
                "scopes": "N/A",
                "error": None,
            }
        if resp.status_code == 401:
            return {"valid": False, "platform": "gitlab", "error": "Invalid or expired GitLab token."}
        return {"valid": False, "platform": "gitlab", "error": f"GitLab API returned status {resp.status_code}"}
    except requests.RequestException as e:
        return {"valid": False, "platform": "gitlab", "error": f"Could not reach GitLab API: {str(e)}"}


def _inject_token_into_url(repo_url: str, token: str, platform: str) -> str:
    if repo_url.startswith("https://"):
        if platform == "github":
            return repo_url.replace("https://", f"https://{token}@")
        if platform == "gitlab":
            return repo_url.replace("https://", f"https://oauth2:{token}@")
    return repo_url


def _job_dir(job_id: str) -> str:
    return os.path.join(JOBS_DIR, job_id)


def _job_status_file(job_id: str) -> str:
    return os.path.join(_job_dir(job_id), "status.json")


def _job_stdout_file(job_id: str) -> str:
    return os.path.join(_job_dir(job_id), "stdout.log")


def _job_stderr_file(job_id: str) -> str:
    return os.path.join(_job_dir(job_id), "stderr.log")


def _process_is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def ask_ollama(prompt: str) -> dict:
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }

    resp = requests.post(OLLAMA_URL, json=payload, timeout=180)
    resp.raise_for_status()
    data = resp.json()

    return {
        "success": True,
        "model": OLLAMA_MODEL,
        "response": data.get("response", ""),
    }


# ----------------------------
# Basic tools
# ----------------------------
@mcp.tool()
def ping() -> dict:
    return {"success": True, "message": "MCP server is running"}


@mcp.tool()
def llm_analyze_text(text: str) -> dict:
    prompt = f"""
You are a senior application security engineer.

Analyze the following security-related content.
Return:
1. Summary
2. Key risks
3. Severity
4. Recommended remediation

Content:
{text}
"""
    return ask_ollama(prompt)


# ----------------------------
# Async repo clone tools
# ----------------------------
@mcp.tool()
def clone_repo_with_token_async(
    repo_url: str,
    token: str,
    repo_name: str,
    branch: str = "",
    delete_existing: bool = False,
) -> dict:
    """
    Validate a GitHub or GitLab PAT, then clone the repo in background.
    """
    if not _tool_exists("git"):
        return {"success": False, "error": "git is not installed or not in PATH"}

    platform = _detect_platform(repo_url)
    if platform == "unknown":
        return {
            "success": False,
            "error": "Could not detect platform from URL. URL must contain github.com or gitlab.com."
        }

    validation = _validate_github_token(token) if platform == "github" else _validate_gitlab_token(token)
    if not validation["valid"]:
        return {
            "success": False,
            "stage": "token_validation",
            "platform": platform,
            "error": validation["error"],
            "message": "Token validation failed. Repo was not cloned."
        }

    try:
        dest = _safe_repo_path(_repo_dest(repo_name))
    except ValueError as e:
        return {"success": False, "error": str(e)}

    if os.path.exists(dest):
        if delete_existing:
            shutil.rmtree(dest)
        else:
            return {
                "success": False,
                "error": f"Destination already exists: {dest}. Set delete_existing=True to overwrite."
            }

    job_id = f"clone_{repo_name}_{_timestamp()}"
    job_dir = _job_dir(job_id)
    os.makedirs(job_dir, exist_ok=True)

    stdout_file = _job_stdout_file(job_id)
    stderr_file = _job_stderr_file(job_id)
    status_file = _job_status_file(job_id)

    authenticated_url = _inject_token_into_url(repo_url, token, platform)
    cmd = ["git", "clone"]
    if branch:
        cmd.extend(["--branch", branch])
    cmd.extend([authenticated_url, dest])

    with open(stdout_file, "w", encoding="utf-8") as out, open(stderr_file, "w", encoding="utf-8") as err:
        proc = subprocess.Popen(cmd, stdout=out, stderr=err, text=True)

    status = {
        "job_id": job_id,
        "type": "git_clone_with_token",
        "platform": platform,
        "authenticated_as": validation.get("username", ""),
        "repo_name": repo_name,
        "repo_url": repo_url,
        "repo_path": dest,
        "branch": branch or "default",
        "pid": proc.pid,
        "started_at": datetime.now().isoformat(),
        "status": "running",
        "stdout_file": stdout_file,
        "stderr_file": stderr_file,
    }
    _write_json(status_file, status)

    return {
        "success": True,
        "message": f"Token validated and clone started in background for {validation.get('username', '')}",
        "job_id": job_id,
        "repo_path": dest,
        "status_file": status_file,
    }


@mcp.tool()
def git_clone_repo_async(
    repo_url: str,
    repo_name: str,
    branch: str = "",
    delete_existing: bool = False,
) -> dict:
    """
    Clone a git repository in background into source_code/<repo_name>
    """
    if not _tool_exists("git"):
        return {"success": False, "error": "git not installed or not in PATH"}

    dest = _safe_repo_path(_repo_dest(repo_name))

    if os.path.exists(dest):
        if delete_existing:
            shutil.rmtree(dest)
        else:
            return {
                "success": False,
                "error": f"Destination already exists: {dest}. Use delete_existing=True or delete_repo_folder first."
            }

    job_id = f"clone_{repo_name}_{_timestamp()}"
    job_dir = _job_dir(job_id)
    os.makedirs(job_dir, exist_ok=True)

    stdout_file = _job_stdout_file(job_id)
    stderr_file = _job_stderr_file(job_id)
    status_file = _job_status_file(job_id)

    cmd = ["git", "clone"]
    if branch:
        cmd.extend(["--branch", branch])
    cmd.extend([repo_url, dest])

    with open(stdout_file, "w", encoding="utf-8") as out, open(stderr_file, "w", encoding="utf-8") as err:
        proc = subprocess.Popen(cmd, stdout=out, stderr=err, text=True)

    status = {
        "job_id": job_id,
        "type": "git_clone",
        "repo_name": repo_name,
        "repo_url": repo_url,
        "repo_path": dest,
        "branch": branch or "default",
        "pid": proc.pid,
        "started_at": datetime.now().isoformat(),
        "status": "running",
        "stdout_file": stdout_file,
        "stderr_file": stderr_file,
    }
    _write_json(status_file, status)

    return {
        "success": True,
        "message": "Clone started in background",
        "job_id": job_id,
        "repo_path": dest,
        "status_file": status_file,
    }


@mcp.tool()
def clone_job_status(job_id: str) -> dict:
    """
    Check background clone job status.
    """
    status_file = _job_status_file(job_id)
    stdout_file = _job_stdout_file(job_id)
    stderr_file = _job_stderr_file(job_id)

    if not os.path.exists(status_file):
        return {"success": False, "error": "Job not found"}

    with open(status_file, "r", encoding="utf-8") as f:
        status = json.load(f)

    pid = status.get("pid")
    repo_path = status.get("repo_path", "")

    running = _process_is_running(pid) if pid else False
    clone_done = os.path.isdir(repo_path) and os.path.exists(os.path.join(repo_path, ".git"))

    if running:
        current_status = "running"
    elif clone_done:
        current_status = "completed"
    else:
        current_status = "failed"

    status["status"] = current_status
    status["checked_at"] = datetime.now().isoformat()
    _write_json(status_file, status)

    return {
        "success": True,
        "job_id": job_id,
        "status": current_status,
        "repo_path": repo_path,
        "stdout": _read_text_file(stdout_file, max_len=4000) if os.path.exists(stdout_file) else "",
        "stderr": _read_text_file(stderr_file, max_len=4000) if os.path.exists(stderr_file) else "",
    }


@mcp.tool()
def list_cloned_repos() -> dict:
    """
    List cloned repos under source_code.
    """
    base = _safe_repo_path(SOURCE_CODE_BASE_DIR)
    repos = []

    for name in os.listdir(base):
        full_path = os.path.join(base, name)
        if os.path.isdir(full_path):
            repos.append({
                "name": name,
                "path": full_path,
                "modified_time": os.path.getmtime(full_path),
            })

    repos = sorted(repos, key=lambda x: x["modified_time"], reverse=True)

    return {
        "success": True,
        "count": len(repos),
        "repos": repos,
    }


@mcp.tool()
def delete_repo_folder(repo_name: str) -> dict:
    """
    Delete a cloned repo folder from source_code/<repo_name>
    """
    target = _safe_repo_path(_repo_dest(repo_name))

    if not os.path.exists(target):
        return {"success": False, "error": f"Repo folder not found: {target}"}

    shutil.rmtree(target)
    return {"success": True, "deleted_path": target}


# ----------------------------
# Semgrep
# ----------------------------
@mcp.tool()
def semgrep_scan(target_path: str, rules: str = "p/owasp-top-ten") -> dict:
    """
    Run Semgrep on a folder and save JSON output.
    """
    if not _tool_exists("semgrep"):
        return {"success": False, "error": "semgrep not installed or not in PATH"}

    target = _safe_path(target_path)
    output = os.path.join(SAST_RAW_DIR, f"semgrep_{_timestamp()}.json")

    cmd = ["semgrep", "--config", rules, "--json", "--output", output, target]
    proc = subprocess.run(cmd, capture_output=True, text=True)

    return {
        "success": proc.returncode == 0,
        "tool": "Semgrep",
        "file": output if os.path.exists(output) else "",
        "stdout": proc.stdout[:5000],
        "stderr": proc.stderr[:5000],
        "command": " ".join(cmd),
    }


@mcp.tool()
def generate_semgrep_report_json() -> dict:
    latest = _latest_file(SAST_RAW_DIR, "semgrep_*.json")
    if not latest:
        return {"success": False, "error": "No Semgrep report found"}

    with open(latest, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = data.get("results", [])
    severity_counts = {}

    for item in results:
        sev = item.get("extra", {}).get("severity", "Medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    report = {
        "tool": "Semgrep",
        "generated_at": datetime.now().isoformat(),
        "source_file": latest,
        "total_findings": len(results),
        "severity_breakdown": severity_counts,
        "findings": results,
    }

    out_file = os.path.join(SAST_REPORTS_DIR, f"semgrep_report_{_timestamp()}.json")
    _write_json(out_file, report)

    return {"success": True, "tool": "Semgrep", "file": out_file, "total_findings": len(results)}


# ----------------------------
# Gitleaks
# ----------------------------
@mcp.tool()
def gitleaks_scan(target_path: str = "", mode: str = "auto") -> dict:
    """
    mode:
    - run  -> run scan
    - read -> read latest report
    - auto -> run if target_path provided, else read
    """
    if not _tool_exists("gitleaks"):
        return {"success": False, "error": "gitleaks not installed or not in PATH"}

    if mode not in ["auto", "run", "read"]:
        return {"success": False, "error": "mode must be one of: auto, run, read"}

    if mode == "read" or (mode == "auto" and not target_path):
        latest = _latest_file(SECRETS_RAW_DIR, "gitleaks_*.json")
        if not latest:
            return {"success": False, "error": "No Gitleaks report found"}
        return {
            "success": True,
            "mode": "read",
            "tool": "Gitleaks",
            "file": latest,
            "content": _read_text_file(latest),
        }

    target = _safe_path(target_path)
    if not os.path.exists(target):
        return {"success": False, "error": f"Target path does not exist: {target}"}

    output = os.path.join(SECRETS_RAW_DIR, f"gitleaks_{_timestamp()}.json")

    cmd = [
        "gitleaks",
        "detect",
        "--source", target,
        "--report-format", "json",
        "--report-path", output,
    ]

    result = _run_command(cmd)

    return {
        "success": result["success"],
        "mode": "run",
        "tool": "Gitleaks",
        "file": output if os.path.exists(output) else "",
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "command": result["command"],
    }


@mcp.tool()
def generate_gitleaks_report_json() -> dict:
    latest = _latest_file(SECRETS_RAW_DIR, "gitleaks_*.json")
    if not latest:
        return {"success": False, "error": "No Gitleaks report found"}

    with open(latest, "r", encoding="utf-8") as f:
        data = json.load(f)

    report = {
        "tool": "Gitleaks",
        "generated_at": datetime.now().isoformat(),
        "source_file": latest,
        "total_findings": len(data),
        "severity_breakdown": {"High": len(data)},
        "findings": data,
    }

    out_file = os.path.join(SECRETS_REPORTS_DIR, f"gitleaks_report_{_timestamp()}.json")
    _write_json(out_file, report)

    return {"success": True, "tool": "Gitleaks", "file": out_file, "total_findings": len(data)}


# ----------------------------
# Syft
# ----------------------------
@mcp.tool()
def syft_scan(target_path: str = "", mode: str = "auto") -> dict:
    """
    mode:
    - run  -> generate SBOM JSON
    - read -> read latest SBOM JSON
    - auto -> run if target_path provided, else read
    """
    if not _tool_exists("syft"):
        return {"success": False, "error": "syft not installed or not in PATH"}

    if mode not in ["auto", "run", "read"]:
        return {"success": False, "error": "mode must be one of: auto, run, read"}

    if mode == "read" or (mode == "auto" and not target_path):
        latest = _latest_file(SCA_RAW_DIR, "sbom_*.json")
        if not latest:
            return {"success": False, "error": "No SBOM file found"}
        return {
            "success": True,
            "mode": "read",
            "tool": "Syft",
            "file": latest,
            "content": _read_text_file(latest),
        }

    target = _safe_path(target_path)
    if not os.path.exists(target):
        return {"success": False, "error": f"Target path does not exist: {target}"}

    output = os.path.join(SCA_RAW_DIR, f"sbom_{_timestamp()}.json")
    cmd = ["syft", f"dir:{target}", "-o", "json"]

    proc = subprocess.run(cmd, capture_output=True, text=True)

    if proc.returncode == 0:
        with open(output, "w", encoding="utf-8") as f:
            f.write(proc.stdout)

    return {
        "success": proc.returncode == 0,
        "mode": "run",
        "tool": "Syft",
        "file": output if os.path.exists(output) else "",
        "stdout": proc.stdout[:5000],
        "stderr": proc.stderr[:5000],
        "command": " ".join(cmd),
    }


@mcp.tool()
def generate_syft_report_json() -> dict:
    latest = _latest_file(SCA_RAW_DIR, "sbom_*.json")
    if not latest:
        return {"success": False, "error": "No Syft SBOM found"}

    with open(latest, "r", encoding="utf-8") as f:
        data = json.load(f)

    artifacts = data.get("artifacts", [])
    report = {
        "tool": "Syft",
        "generated_at": datetime.now().isoformat(),
        "source_file": latest,
        "total_components": len(artifacts),
        "sbom": data,
    }

    out_file = os.path.join(SCA_REPORTS_DIR, f"syft_report_{_timestamp()}.json")
    _write_json(out_file, report)

    return {"success": True, "tool": "Syft", "file": out_file, "total_components": len(artifacts)}


# ----------------------------
# Grype
# ----------------------------
@mcp.tool()
def grype_scan(sbom_path: str = "", target_path: str = "", mode: str = "auto") -> dict:
    """
    mode:
    - run  -> run new scan
    - read -> read latest Grype report
    - auto -> use sbom_path or target_path if given, else read latest
    """
    if not _tool_exists("grype"):
        return {"success": False, "error": "grype not installed or not in PATH"}

    if mode not in ["auto", "run", "read"]:
        return {"success": False, "error": "mode must be one of: auto, run, read"}

    if mode == "read" or (mode == "auto" and not sbom_path and not target_path):
        latest = _latest_file(SCA_RAW_DIR, "grype_*.json")
        if not latest:
            return {"success": False, "error": "No Grype report found"}
        return {
            "success": True,
            "mode": "read",
            "tool": "Grype",
            "file": latest,
            "content": _read_text_file(latest),
        }

    output = os.path.join(SCA_RAW_DIR, f"grype_{_timestamp()}.json")

    if sbom_path:
        safe_sbom = _safe_path(sbom_path)
        if not os.path.exists(safe_sbom):
            return {"success": False, "error": f"SBOM file not found: {safe_sbom}"}
        cmd = ["grype", f"sbom:{safe_sbom}", "-o", "json"]
    elif target_path:
        safe_target = _safe_path(target_path)
        if not os.path.exists(safe_target):
            return {"success": False, "error": f"Target path does not exist: {safe_target}"}
        cmd = ["grype", f"dir:{safe_target}", "-o", "json"]
    else:
        return {"success": False, "error": "Provide either sbom_path or target_path"}

    proc = subprocess.run(cmd, capture_output=True, text=True)

    if proc.returncode == 0:
        with open(output, "w", encoding="utf-8") as f:
            f.write(proc.stdout)

    return {
        "success": proc.returncode == 0,
        "mode": "run",
        "tool": "Grype",
        "file": output if os.path.exists(output) else "",
        "stdout": proc.stdout[:5000],
        "stderr": proc.stderr[:5000],
        "command": " ".join(cmd),
    }


@mcp.tool()
def generate_grype_report_json() -> dict:
    latest = _latest_file(SCA_RAW_DIR, "grype_*.json")
    if not latest:
        return {"success": False, "error": "No Grype report found"}

    with open(latest, "r", encoding="utf-8") as f:
        data = json.load(f)

    matches = data.get("matches", [])
    severity_counts = {}

    for item in matches:
        sev = item.get("vulnerability", {}).get("severity", "Medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    report = {
        "tool": "Grype",
        "generated_at": datetime.now().isoformat(),
        "source_file": latest,
        "total_findings": len(matches),
        "severity_breakdown": severity_counts,
        "findings": matches,
    }

    out_file = os.path.join(SCA_REPORTS_DIR, f"grype_report_{_timestamp()}.json")
    _write_json(out_file, report)

    return {"success": True, "tool": "Grype", "file": out_file, "total_findings": len(matches)}


# ----------------------------
# Source code pipeline
# ----------------------------
@mcp.tool()
def source_code_security_pipeline(target_path: str, mode: str = "auto") -> dict:
    """
    Run Gitleaks + Syft + Grype on source code.
    """
    if mode == "read":
        return {
            "success": True,
            "mode": "read",
            "gitleaks": gitleaks_scan(mode="read"),
            "syft": syft_scan(mode="read"),
            "grype": grype_scan(mode="read"),
        }

    gitleaks_result = gitleaks_scan(target_path=target_path, mode="run")
    syft_result = syft_scan(target_path=target_path, mode="run")

    sbom_file = syft_result.get("file", "")
    if sbom_file:
        grype_result = grype_scan(sbom_path=sbom_file, mode="run")
    else:
        grype_result = {
            "success": False,
            "error": "Skipping Grype because Syft SBOM generation failed",
        }

    return {
        "success": True,
        "mode": "run",
        "target_path": target_path,
        "gitleaks": gitleaks_result,
        "syft": syft_result,
        "grype": grype_result,
    }


@mcp.tool()
def run_source_scan_after_clone(job_id: str) -> dict:
    """
    If clone is complete, run source code security pipeline.
    """
    job_status = clone_job_status(job_id)

    if not job_status.get("success"):
        return job_status

    if job_status.get("status") != "completed":
        return {
            "success": False,
            "error": f"Clone job is not complete. Current status: {job_status.get('status')}"
        }

    repo_path = job_status.get("repo_path")
    return source_code_security_pipeline(target_path=repo_path, mode="run")


# ----------------------------
# ZAP manual result readers
# ----------------------------
@mcp.tool()
def list_zap_results() -> dict:
    if not os.path.exists(ZAP_RESULTS_DIR):
        return {"success": False, "error": "ZAP results folder not found"}

    files = []
    for f in os.listdir(ZAP_RESULTS_DIR):
        full_path = os.path.join(ZAP_RESULTS_DIR, f)
        if os.path.isfile(full_path):
            files.append({
                "name": f,
                "path": full_path,
                "modified_time": os.path.getmtime(full_path),
                "size": os.path.getsize(full_path),
            })

    files = sorted(files, key=lambda x: x["modified_time"], reverse=True)

    return {
        "success": True,
        "count": len(files),
        "files": files,
    }


@mcp.tool()
def read_zap_csv(file_name: str) -> dict:
    file_path = os.path.abspath(os.path.join(ZAP_RESULTS_DIR, file_name))

    if not file_path.startswith(os.path.abspath(ZAP_RESULTS_DIR) + os.sep):
        return {"success": False, "error": "Invalid file path"}

    if not os.path.isfile(file_path):
        return {"success": False, "error": "File not found"}

    return {
        "success": True,
        "file_name": file_name,
        "file_path": file_path,
        "content": _read_text_file(file_path),
    }


@mcp.tool()
def read_latest_zap_csv() -> dict:
    if not os.path.exists(ZAP_RESULTS_DIR):
        return {"success": False, "error": "ZAP results folder not found"}

    csv_files = []
    for f in os.listdir(ZAP_RESULTS_DIR):
        full_path = os.path.join(ZAP_RESULTS_DIR, f)
        if os.path.isfile(full_path) and f.lower().endswith(".csv"):
            csv_files.append(full_path)

    if not csv_files:
        return {"success": False, "error": "No CSV files found"}

    latest_file = max(csv_files, key=os.path.getmtime)

    return {
        "success": True,
        "file_name": os.path.basename(latest_file),
        "file_path": latest_file,
        "content": _read_text_file(latest_file),
    }


@mcp.tool()
def llm_analyze_zap_csv(csv_text: str) -> dict:
    prompt = f"""
You are a senior web application security engineer.

Analyze the following OWASP ZAP CSV results.

Provide:
1. Executive summary
2. Most important vulnerabilities
3. Risk severity
4. Possible false positives
5. Recommended remediation
6. Suggested manual validation steps

ZAP CSV:
{csv_text}
"""
    return ask_ollama(prompt)


@mcp.tool()
def analyze_latest_zap_csv() -> dict:
    if not os.path.exists(ZAP_RESULTS_DIR):
        return {"success": False, "error": "ZAP results folder not found"}

    csv_files = []
    for f in os.listdir(ZAP_RESULTS_DIR):
        full_path = os.path.join(ZAP_RESULTS_DIR, f)
        if os.path.isfile(full_path) and f.lower().endswith(".csv"):
            csv_files.append(full_path)

    if not csv_files:
        return {"success": False, "error": "No CSV files found"}

    latest_file = max(csv_files, key=os.path.getmtime)
    content = _read_text_file(latest_file)

    analysis = ask_ollama(f"""
You are a senior web application security engineer.

Analyze this OWASP ZAP CSV export.

Provide:
1. Executive summary
2. Top risks
3. Severity ranking
4. Likely false positives
5. Remediation advice
6. Suggested manual verification steps

ZAP CSV:
{content}
""")

    return {
        "success": True,
        "file_name": os.path.basename(latest_file),
        "file_path": latest_file,
        "analysis": analysis,
    }


@mcp.tool()
def generate_zap_report_json(file_name: str = "") -> dict:
    if file_name:
        file_path = os.path.abspath(os.path.join(ZAP_RESULTS_DIR, file_name))
        if not file_path.startswith(os.path.abspath(ZAP_RESULTS_DIR) + os.sep):
            return {"success": False, "error": "Invalid file path"}
        if not os.path.isfile(file_path):
            return {"success": False, "error": "ZAP file not found"}
    else:
        csv_files = []
        for f in os.listdir(ZAP_RESULTS_DIR):
            full_path = os.path.join(ZAP_RESULTS_DIR, f)
            if os.path.isfile(full_path) and f.lower().endswith(".csv"):
                csv_files.append(full_path)

        if not csv_files:
            return {"success": False, "error": "No ZAP CSV files found"}

        file_path = max(csv_files, key=os.path.getmtime)

    content = _read_text_file(file_path)

    report = {
        "tool": "ZAP",
        "generated_at": datetime.now().isoformat(),
        "source_file": file_path,
        "format": "csv",
        "content": content,
    }

    out_file = os.path.join(DAST_REPORTS_DIR, f"zap_report_{_timestamp()}.json")
    _write_json(out_file, report)

    return {
        "success": True,
        "tool": "ZAP",
        "file": out_file,
        "source_file": file_path,
    }


# ----------------------------
# JADX
# ----------------------------
@mcp.tool()
def jadx_decompile(apk_path: str, project_name: str = "jadx_scan") -> dict:
    apk_path = _safe_path(apk_path)

    out_dir = os.path.join(MOBILE_MCP_WORK_DIR, project_name)

    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)

    os.makedirs(out_dir)

    cmd = ["jadx", "-d", out_dir, apk_path]
    process = subprocess.run(cmd, capture_output=True, text=True)

    return {
        "success": process.returncode == 0,
        "apk": apk_path,
        "output_directory": out_dir,
        "stdout": process.stdout[:3000],
        "stderr": process.stderr[:3000],
        "command": " ".join(cmd),
    }


# ----------------------------
# MobSF
# ----------------------------
@mcp.tool()
def mobsf_scan(apk_path: str) -> dict:
    apk_path = _safe_path(apk_path)

    if not MOBSF_API_KEY:
        return {"success": False, "error": "MOBSF_API_KEY is not set."}

    headers = {"Authorization": MOBSF_API_KEY}

    try:
        with open(apk_path, "rb") as f:
            files = {
                "file": (os.path.basename(apk_path), f, "application/octet-stream")
            }
            upload_resp = requests.post(
                f"{MOBSF_URL}/api/v1/upload",
                files=files,
                headers=headers,
                timeout=300,
            )
        upload_resp.raise_for_status()
        upload = upload_resp.json()

        if "hash" not in upload or "scan_type" not in upload:
            return {
                "success": False,
                "error": "Unexpected upload response from MobSF",
                "upload_response": upload,
            }

        scan_data = {
            "hash": upload["hash"],
            "scan_type": upload["scan_type"],
        }
        scan_resp = requests.post(
            f"{MOBSF_URL}/api/v1/scan",
            data=scan_data,
            headers=headers,
            timeout=600,
        )
        scan_resp.raise_for_status()
        scan_json = scan_resp.json()

        report_resp = requests.post(
            f"{MOBSF_URL}/api/v1/report_json",
            data={"hash": upload["hash"]},
            headers=headers,
            timeout=300,
        )
        report_resp.raise_for_status()
        report = report_resp.json()

        output_file = os.path.join(MOBILE_RAW_DIR, f"mobsf_{_timestamp()}.json")
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        report_text = json.dumps(report, indent=2)
        if len(report_text) > 15000:
            report_text = report_text[:15000] + "\n...<truncated>..."

        return {
            "success": True,
            "file": apk_path,
            "raw_report_file": output_file,
            "hash": upload["hash"],
            "scan_summary": {
                "high": report.get("high", 0),
                "medium": report.get("medium", 0),
                "low": report.get("low", 0),
            },
            "scan_response": scan_json,
            "report": report_text,
        }

    except requests.RequestException as e:
        return {"success": False, "error": f"MobSF request failed: {str(e)}"}
    except ValueError as e:
        return {"success": False, "error": f"Invalid JSON returned by MobSF: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def llm_analyze_mobsf(report: str) -> dict:
    prompt = f"""
You are a mobile security expert.

Analyze this MobSF report.

Provide:
1. Critical vulnerabilities
2. Risk summary
3. MASVS mapping
4. Recommended fixes

Report:
{report}
"""
    return ask_ollama(prompt)


@mcp.tool()
def generate_mobsf_report_json() -> dict:
    latest = _latest_file(MOBILE_RAW_DIR, "mobsf_*.json")
    if not latest:
        return {"success": False, "error": "No MobSF raw report found"}

    with open(latest, "r", encoding="utf-8") as f:
        data = json.load(f)

    report = {
        "tool": "MobSF",
        "generated_at": datetime.now().isoformat(),
        "source_file": latest,
        "scan_summary": {
            "high": data.get("high", 0),
            "medium": data.get("medium", 0),
            "low": data.get("low", 0),
        },
        "report": data,
    }

    out_file = os.path.join(MOBILE_REPORTS_DIR, f"mobsf_report_{_timestamp()}.json")
    _write_json(out_file, report)

    return {"success": True, "tool": "MobSF", "file": out_file}


# ----------------------------
# Normalization
# ----------------------------
@mcp.tool()
def normalize_gitleaks() -> dict:
    latest = _latest_file(SECRETS_RAW_DIR, "gitleaks_*.json")
    if not latest:
        return {"success": False, "error": "No Gitleaks report found"}

    with open(latest, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = []
    for i, item in enumerate(data, start=1):
        findings.append({
            "finding_id": _generate_finding_id("SEC", i),
            "source_type": "Secrets",
            "tool": "Gitleaks",
            "severity": "High",
            "title": item.get("Description", "Secret detected"),
            "location": f"{item.get('File')}:{item.get('StartLine')}",
            "description": item.get("Match", ""),
            "status": "Open",
        })

    out_file = os.path.join(SECRETS_RAW_DIR, "normalized_gitleaks.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    return {"success": True, "count": len(findings), "file": out_file}


@mcp.tool()
def normalize_grype() -> dict:
    latest = _latest_file(SCA_RAW_DIR, "grype_*.json")
    if not latest:
        return {"success": False, "error": "No Grype report found"}

    with open(latest, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = []
    matches = data.get("matches", [])

    for i, item in enumerate(matches, start=1):
        vuln = item.get("vulnerability", {})
        artifact = item.get("artifact", {})

        findings.append({
            "finding_id": _generate_finding_id("SCA", i),
            "source_type": "SCA",
            "tool": "Grype",
            "severity": vuln.get("severity", "Medium"),
            "title": vuln.get("id"),
            "component": artifact.get("name"),
            "version": artifact.get("version"),
            "description": vuln.get("description", ""),
            "status": "Open",
        })

    out_file = os.path.join(SCA_RAW_DIR, "normalized_grype.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    return {"success": True, "count": len(findings), "file": out_file}


@mcp.tool()
def normalize_semgrep() -> dict:
    latest = _latest_file(SAST_RAW_DIR, "semgrep_*.json")
    if not latest:
        return {"success": False, "error": "No Semgrep report found"}

    with open(latest, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = []
    results = data.get("results", [])

    for i, item in enumerate(results, start=1):
        findings.append({
            "finding_id": _generate_finding_id("SAST", i),
            "source_type": "SAST",
            "tool": "Semgrep",
            "severity": item.get("extra", {}).get("severity", "Medium"),
            "title": item.get("check_id"),
            "location": f"{item.get('path')}:{item.get('start', {}).get('line')}",
            "description": item.get("extra", {}).get("message", ""),
            "status": "Open",
        })

    out_file = os.path.join(SAST_RAW_DIR, "normalized_semgrep.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    return {"success": True, "count": len(findings), "file": out_file}


# ----------------------------
# Consolidation / reporting
# ----------------------------
@mcp.tool()
def merge_all_findings() -> dict:
    all_files = [
        os.path.join(SECRETS_RAW_DIR, "normalized_gitleaks.json"),
        os.path.join(SCA_RAW_DIR, "normalized_grype.json"),
        os.path.join(SAST_RAW_DIR, "normalized_semgrep.json"),
    ]

    merged = []
    for file in all_files:
        if os.path.exists(file):
            with open(file, "r", encoding="utf-8") as f:
                data = json.load(f)
            merged.extend(data)

    out_file = os.path.join(CONSOLIDATED_DIR, "findings.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2)

    return {"success": True, "total_findings": len(merged), "file": out_file}


@mcp.tool()
def generate_summary() -> dict:
    file = os.path.join(CONSOLIDATED_DIR, "findings.json")

    if not os.path.exists(file):
        return {"success": False, "error": "Run merge_all_findings first"}

    with open(file, "r", encoding="utf-8") as f:
        data = json.load(f)

    severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

    for finding in data:
        sev = finding.get("severity", "Medium")
        severity[sev] = severity.get(sev, 0) + 1

    summary = {"total": len(data), "severity": severity}

    out = os.path.join(CONSOLIDATED_DIR, "summary.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    return {"success": True, "file": out, "summary": summary}


@mcp.tool()
def generate_defects() -> dict:
    file = os.path.join(CONSOLIDATED_DIR, "findings.json")

    if not os.path.exists(file):
        return {"success": False, "error": "Run merge_all_findings first"}

    with open(file, "r", encoding="utf-8") as f:
        data = json.load(f)

    defects = []
    for i, item in enumerate(data, start=1):
        defects.append({
            "defect_id": f"DEF-{i:03}",
            "finding_id": item.get("finding_id", ""),
            "title": item.get("title", ""),
            "severity": item.get("severity", "Medium"),
            "status": "Open",
            "owner": "Unassigned",
        })

    out = os.path.join(CONSOLIDATED_DIR, "defect_tracker.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(defects, f, indent=2)

    return {"success": True, "file": out, "count": len(defects)}


@mcp.tool()
def generate_dashboard_json() -> dict:
    findings_file = os.path.join(CONSOLIDATED_DIR, "findings.json")
    defects_file = os.path.join(CONSOLIDATED_DIR, "defect_tracker.json")

    if not os.path.exists(findings_file):
        return {"success": False, "error": "findings.json not found"}

    with open(findings_file, "r", encoding="utf-8") as f:
        findings = json.load(f)

    defects = []
    if os.path.exists(defects_file):
        with open(defects_file, "r", encoding="utf-8") as f:
            defects = json.load(f)

    severity_breakdown = {}
    findings_by_source = {}

    for finding in findings:
        sev = finding.get("severity", "Medium")
        source = finding.get("source_type", "Unknown")
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
        findings_by_source[source] = findings_by_source.get(source, 0) + 1

    severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    top_findings = sorted(
        findings,
        key=lambda x: severity_rank.get(x.get("severity", "Info"), 0),
        reverse=True,
    )[:10]

    defect_status = {}
    for defect in defects:
        status = defect.get("status", "Open")
        defect_status[status] = defect_status.get(status, 0) + 1

    dashboard = {
        "application": "AI AppSec Assessment",
        "generated_at": datetime.now().isoformat(),
        "overall_risk": "High" if severity_breakdown.get("Critical", 0) or severity_breakdown.get("High", 0) else "Medium",
        "total_findings": len(findings),
        "severity_breakdown": severity_breakdown,
        "findings_by_source": findings_by_source,
        "defect_status": defect_status,
        "top_findings": top_findings,
    }

    out_file = os.path.join(DASHBOARD_EXPORT_DIR, "dashboard.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(dashboard, f, indent=2)

    return {"success": True, "file": out_file, "total_findings": len(findings)}


@mcp.tool()
def generate_report_json() -> dict:
    findings_file = os.path.join(CONSOLIDATED_DIR, "findings.json")
    summary_file = os.path.join(CONSOLIDATED_DIR, "summary.json")
    defects_file = os.path.join(CONSOLIDATED_DIR, "defect_tracker.json")

    if not os.path.exists(findings_file):
        return {"success": False, "error": "findings.json not found"}

    with open(findings_file, "r", encoding="utf-8") as f:
        findings = json.load(f)

    summary = {}
    if os.path.exists(summary_file):
        with open(summary_file, "r", encoding="utf-8") as f:
            summary = json.load(f)

    defects = []
    if os.path.exists(defects_file):
        with open(defects_file, "r", encoding="utf-8") as f:
            defects = json.load(f)

    report = {
        "title": "AI-Assisted Application Security Assessment Report",
        "generated_at": datetime.now().isoformat(),
        "summary": summary,
        "findings": findings,
        "defects": defects,
    }

    out_file = os.path.join(CONSOLIDATED_DIR, "report_data.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return {"success": True, "file": out_file}


@mcp.tool()
def generate_pdf_report() -> dict:
    script_path = os.path.join(BASE_SCAN_DIR, "templates", "generate_pdf_report.py")

    if not os.path.exists(script_path):
        return {"success": False, "error": "PDF generator script not found"}

    cmd = ["python3", script_path]
    proc = subprocess.run(cmd, capture_output=True, text=True)

    return {
        "success": proc.returncode == 0,
        "stdout": proc.stdout[:3000],
        "stderr": proc.stderr[:3000],
        "pdf_file": os.path.join(CONSOLIDATED_REPORTS_DIR, "Executive_Report.pdf"),
    }


# ----------------------------
# HTTP app
# ----------------------------
app = mcp.http_app(path="/mcp/")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

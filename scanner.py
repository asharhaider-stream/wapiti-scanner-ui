import subprocess
import json
import re
import os
import time
import signal
import threading

# Module mapping for Wapiti
MODULE_MAP = {
    "all": "all",
    "sql": "sql",
    "xss": "xss",
    "file": "file",
    "exec": "exec",
    "blindsql": "blindsql",
    "csrf": "csrf",
    "idor": "idor",
    "cmd": "cmd"
}

# Display names for UI
MODULE_DISPLAY = {
    "all": "All Modules",
    "sql": "SQL Injection",
    "xss": "Cross-Site Scripting",
    "file": "File Disclosure",
    "exec": "Command Execution",
    "blindsql": "Blind SQL Injection",
    "csrf": "CSRF",
    "idor": "IDOR",
    "cmd": "Command Injection"
}

def run_scan(scan_request):
    """
    Run Wapiti scan with specified modules
    scan_request: {target_url: str, modules: list, depth: int, timeout: int}
    """
    target_url = scan_request.target_url
    modules = scan_request.modules
    depth = scan_request.depth
    timeout = getattr(scan_request, 'timeout', 600)  # Default 600 seconds

    # Build Wapiti command
    cmd = ["wapiti", "-u", target_url, "-f", "json"]

    # Add modules
    if modules and "all" not in modules:
        for module in modules:
            if module in MODULE_MAP and module != "all":
                cmd.extend(["-m", module])
    else:
        cmd.extend(["-m", "all"])

    # Add depth
    if depth:
        cmd.extend(["-d", str(depth)])

    print(f"Running: {' '.join(cmd)}")
    print(f"Timeout: {timeout} seconds")

    try:
        # Start the process
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )

        # Timer to kill the process after timeout
        timer = threading.Timer(timeout, kill_process, args=[process])
        timer.start()

        # Wait for process to complete
        stdout, stderr = process.communicate()
        timer.cancel()  # Cancel timer if process completed

        output = stdout + stderr

        # Parse vulnerabilities
        vulnerabilities = extract_vulnerabilities(output)

        return {
            "target_url": target_url,
            "modules_run": modules if modules else ["all"],
            "pages_crawled": extract_pages_crawled(output),
            "scan_duration": extract_duration(output),
            "vulnerabilities": vulnerabilities
        }

    except subprocess.TimeoutExpired:
        kill_process(process)
        print("Scan timed out after {} seconds".format(timeout))
        return {
            "target_url": target_url,
            "modules_run": modules if modules else ["all"],
            "pages_crawled": 0,
            "scan_duration": f"Timeout after {timeout}s",
            "vulnerabilities": []
        }
    except Exception as e:
        print(f"Scan error: {e}")
        return None


def kill_process(process):
    """Kill a process and its children"""
    try:
        if os.name == 'nt':  # Windows
            subprocess.run(['taskkill', '/F', '/T', '/PID', str(process.pid)], capture_output=True)
        else:  # Linux/Mac
            import signal
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except Exception as e:
        print(f"Error killing process: {e}")

def extract_vulnerabilities(output):
    """Extract vulnerabilities from Wapiti output"""
    vulnerabilities = []

    # Try to parse JSON output
    try:
        # Look for JSON structure in output
        json_match = re.search(r'\{.*\}', output, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group())
            if "vulnerabilities" in data:
                for vuln in data["vulnerabilities"]:
                    vulnerabilities.append({
                        "type": vuln.get("type", "Unknown"),
                        "url": vuln.get("url", ""),
                        "parameter": vuln.get("parameter", ""),
                        "severity": vuln.get("severity", "low"),
                        "method": vuln.get("method", "GET")
                    })
                return vulnerabilities
    except:
        pass

    # Fallback: Parse text output
    patterns = {
        "SQL Injection": "sql",
        "XSS": "xss",
        "Cross Site Scripting": "xss",
        "File": "file",
        "Command": "cmd",
        "Blind SQL": "blindsql",
        "CSRF": "csrf",
        "IDOR": "idor"
    }

    for pattern, vuln_type in patterns.items():
        if re.search(pattern, output, re.IGNORECASE):
            vulnerabilities.append({
                "type": vuln_type,
                "url": extract_url(output),
                "parameter": extract_parameter(output),
                "severity": extract_severity(output),
                "method": "GET"
            })

    return vulnerabilities


def extract_pages_crawled(output):
    """Extract number of pages crawled"""
    match = re.search(r'(\d+)\s+pages? crawled', output, re.IGNORECASE)
    if match:
        return int(match.group(1))

    # Try to count unique URLs in findings
    urls = re.findall(r'(https?://[^\s"\']+)', output)
    return len(set(urls)) or 1


def extract_duration(output):
    """Extract scan duration"""
    match = re.search(r'duration[:\s]+([\d.]+)\s*(?:s|sec|seconds)', output, re.IGNORECASE)
    if match:
        return f"{match.group(1)}s"
    return "N/A"


def extract_url(output):
    """Extract URL from output"""
    match = re.search(r'(https?://[^\s"\']+)', output)
    return match.group(1) if match else ""


def extract_parameter(output):
    """Extract parameter from output"""
    match = re.search(r'parameter[:\s]+(\w+)', output, re.IGNORECASE)
    return match.group(1) if match else ""


def extract_severity(output):
    """Extract severity from output"""
    if re.search(r'critical', output, re.IGNORECASE):
        return "critical"
    elif re.search(r'high', output, re.IGNORECASE):
        return "high"
    elif re.search(r'medium', output, re.IGNORECASE):
        return "medium"
    elif re.search(r'low', output, re.IGNORECASE):
        return "low"
    return "medium"
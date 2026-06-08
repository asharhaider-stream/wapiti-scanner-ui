import subprocess
import json
import time
import os

def run_scan(scan_request):
    start_time = time.time()
    
    modules = ",".join(scan_request.modules)
    output_path = "report.json"

    command = [
        "wapiti",
        "-u", scan_request.target_url,
        "-m", modules,
        "-d", str(scan_request.depth),
        "--timeout", str(scan_request.timeout),
        "-f", "json",
        "-o", output_path,
        "--flush-session"
    ]
    
    subprocess.run(command, capture_output=True)
    duration = round(time.time() - start_time, 2)
    
    if not os.path.exists(output_path):
        return None

    with open(output_path, "r") as f:
        content = f.read()
        print("RAW REPORT:", content[:500])
        report = json.loads(content)
        
    vulnerabilities = []
    pages_crawled = 0

    try:
        infos = report.get("infos", {})
        pages_crawled = infos.get("nb_urls", 0)

        vulns = report.get("vulnerabilities", {})

        for vuln_type, findings in vulns.items():
            for finding in findings:
                vulnerabilities.append({
                    "type": vuln_type,
                    "url": finding.get("path", ""),
                    "parameter": finding.get("parameter", ""),
                    "severity": "high" if "sql" in vuln_type.lower() else "medium",
                    "method": finding.get("method", "GET")
                })
    except:
        pass    
    
    return {
        "target_url": scan_request.target_url,
        "pages_crawled": pages_crawled,
        "scan_duration": f"{duration}s",
        "modules_run": scan_request.modules,
        "vulnerabilities": vulnerabilities
    }
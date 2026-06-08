from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from schema import ScanRequest, ScanResponse
from scanner import run_scan
from database import init_db, save_scan, get_history, save_findings, get_scan_findings


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(lifespan=lifespan)

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def dashboard():
    return FileResponse("templates/dashboard.html")

@app.post("/scan", response_model=ScanResponse)
def scan(scan_request: ScanRequest):
    result = run_scan(scan_request)

    if result is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=500, detail="Scan failed")

    scan_id = save_scan(
        target_url=result["target_url"],
        modules=",".join(result["modules_run"]),
        pages_crawled=result["pages_crawled"],
        scan_duration=result["scan_duration"],
        vulnerabilities_found=len(result["vulnerabilities"])
    )

    save_findings(scan_id, result["vulnerabilities"])

    return result

@app.get("/history")
def history():
    rows = get_history()
    result = []

    for row in rows:
        result.append({
            "id": row[0],
            "target_url": row[1],
            "modules": row[2],
            "pages_crawled": row[3],
            "scan_duration": row[4],
            "vulnerabilities_found": row[5],
            "scanned_at": row[6]
        })

    return result

@app.get("/history/{scan_id}")
def scan_detail(scan_id: int):
    from database import get_scan_findings
    rows = get_scan_findings(scan_id)
    findings = []

    for row in rows:
        findings.append({
            "id": row[0],
            "scan_id": row[1],
            "type": row[2],
            "url": row[3],
            "parameter": row[4],
            "severity": row[5],
            "method": row[6]
        })

    return findings

@app.get("/analytics")
def analytics():
    conn = __import__('sqlite3').connect("scans.db")
    cursor = conn.cursor()

    cursor.execute("SELECT type, COUNT(*) FROM findings GROUP BY type")
    vuln_types = [{"type": row[0], "count": row[1]} for row in cursor.fetchall()]

    cursor.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
    severity_dist = [{"severity": row[0], "count": row[1]} for row in cursor.fetchall()]

    cursor.execute("SELECT url, COUNT(*) FROM findings GROUP BY url ORDER BY COUNT(*) DESC LIMIT 5")
    top_endpoints = [{"url": row[0], "count": row[1]} for row in cursor.fetchall()]

    cursor.execute("SELECT scanned_at, vulnerabilities_found FROM scans ORDER BY scanned_at ASC")
    scan_trend = [{"scanned_at": row[0], "vulnerabilities_found": row[1]} for row in cursor.fetchall()]

    conn.close()

    return {
        "vuln_types": vuln_types,
        "severity_distribution": severity_dist,
        "top_endpoints": top_endpoints,
        "scan_trend": scan_trend
    }



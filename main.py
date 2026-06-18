from dotenv import load_dotenv
load_dotenv()

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from schema import ScanRequest, ScanResponse
from scanner import run_scan
from database import init_db, save_scan, get_history, save_findings, get_scan_findings, get_analytics_data


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
            "id": row["id"],
            "target_url": row["target_url"],
            "modules": row["modules"],
            "pages_crawled": row["pages_crawled"],
            "scan_duration": row["scan_duration"],
            "vulnerabilities_found": row["vulnerabilities_found"],
            "scanned_at": row["scanned_at"]
        })

    return result

@app.get("/history/{scan_id}")
def scan_detail(scan_id: int):
    rows = get_scan_findings(scan_id)
    findings = []

    for row in rows:
        findings.append({
            "id": row["id"],
            "scan_id": row["scan_id"],
            "type": row["type"],
            "url": row["url"],
            "parameter": row["parameter"],
            "severity": row["severity"],
            "method": row["method"]
        })

    return findings

@app.get("/analytics")
def analytics():
    return get_analytics_data()
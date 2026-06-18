from dotenv import load_dotenv
load_dotenv()

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from schema import ScanRequest, ScanResponse
from scanner import run_scan
from database import (
    init_db, 
    save_scan, 
    save_findings, 
    get_scan_findings, 
    get_analytics_data,
    get_paginated_history,
    get_total_scans
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(lifespan=lifespan)

app.mount("/static", StaticFiles(directory="static"), name="static")


# ============================================
# PAGE ROUTES
# ============================================

@app.get("/")
def dashboard():
    return FileResponse("templates/dashboard.html")

@app.get("/scan-page")
def scan_page():
    return FileResponse("templates/new-scan.html")

@app.get("/history-page")
def history_page():
    return FileResponse("templates/history.html")

@app.get("/history-page/{scan_id}")
def scan_detail_page(scan_id: int):
    return FileResponse("templates/scan-detail.html")

# ============================================
# API ROUTES
# ============================================

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
def history(page: int = 1, limit: int = 10, search: str = None):
    """
    Get paginated scan history
    - page: page number (default: 1)
    - limit: scans per page (default: 10)
    - search: optional URL filter
    """
    offset = (page - 1) * limit
    
    rows = get_paginated_history(limit, offset, search)
    total = get_total_scans(search)
    
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
    
    return {
        "scans": result,
        "total": total,
        "page": page,
        "limit": limit,
        "total_pages": (total + limit - 1) // limit
    }


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
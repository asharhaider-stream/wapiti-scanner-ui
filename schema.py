from pydantic import BaseModel
from typing import List, Optional

class ScanRequest(BaseModel):
    target_url: str
    modules: List[str] = ["all"]
    depth: int = 2
    timeout: int = 600  # Default 10 minutes

class Vulnerability(BaseModel):
    type: str
    url: str
    parameter: str
    severity: str
    method: str

class ScanResponse(BaseModel):
    target_url: str
    pages_crawled: int
    scan_duration: str
    modules_run: List[str]
    vulnerabilities: List[Vulnerability]
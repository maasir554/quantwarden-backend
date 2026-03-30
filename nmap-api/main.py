from __future__ import annotations

from fastapi import FastAPI, HTTPException

from src.nmap_api.ethical_scan import ethical_scan
from src.nmap_api.jobs import job_manager
from src.nmap_api.schemas import (
    EthicalScanRequest,
    EthicalScanResponse,
    ScanJobCreateResponse,
    ScanJobStatusResponse,
    ScanRequest,
    ScanResponse,
)
from src.nmap_api.service import scan_domain

app = FastAPI(
    title="Nmap Security Intelligence API",
    description="Extract critical security and post-quantum safety intelligence from a target domain.",
    version="1.0.0",
)


@app.get("/")
def health() -> dict:
    return {"status": "ok", "service": "nmap-api"}


@app.post("/api/v1/security-intelligence", response_model=ScanResponse)
def security_intelligence(req: ScanRequest) -> ScanResponse:
    return scan_domain(
        domain=req.domain.strip(),
        full_port_scan=req.full_port_scan,
        udp_scan=req.udp_scan,
        response_profile=req.response_profile,
    )


@app.post("/ethical-scan", response_model=EthicalScanResponse)
@app.post("/api/v1/ethical-scan", response_model=EthicalScanResponse)
def ethical_scan_endpoint(req: EthicalScanRequest) -> EthicalScanResponse:
    return ethical_scan(req)


@app.post("/api/v1/scans", response_model=ScanJobCreateResponse)
def create_scan_job(req: ScanRequest) -> ScanJobCreateResponse:
    created = job_manager.submit_scan(req)
    return ScanJobCreateResponse(scan_id=created.scan_id, status=created.status)


@app.get("/api/v1/scans/{scan_id}", response_model=ScanJobStatusResponse)
def get_scan_job(scan_id: str, include_result: bool = True) -> ScanJobStatusResponse:
    try:
        return job_manager.get_job(scan_id=scan_id, include_result=include_result)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"scan_id not found: {scan_id}") from exc

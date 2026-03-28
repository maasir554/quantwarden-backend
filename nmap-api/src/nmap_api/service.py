from __future__ import annotations

import shutil
import socket

from fastapi import HTTPException

from .analysis import apply_response_profile, build_response
from .nmap_runner import run_nmap
from .schemas import ScanResponse


def scan_domain(
    domain: str, full_port_scan: bool, response_profile: str = "full", udp_scan: bool = False
) -> ScanResponse:
    if not domain or "://" in domain:
        raise HTTPException(status_code=400, detail="Provide a bare domain, e.g., example.com")

    if shutil.which("nmap") is None:
        raise HTTPException(status_code=500, detail="nmap is not installed or not in PATH")

    try:
        socket.gethostbyname(domain)
    except socket.gaierror as exc:
        raise HTTPException(status_code=400, detail=f"DNS resolution failed: {exc}") from exc

    try:
        scan_data = run_nmap(domain=domain, full_port_scan=full_port_scan, include_udp=udp_scan)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc

    resp = build_response(domain=domain, scan=scan_data)
    return apply_response_profile(resp, response_profile)

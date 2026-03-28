from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Dict, Literal, Optional
from uuid import uuid4

from .schemas import ScanJobStatusResponse, ScanRequest, ScanResponse
from .service import scan_domain

JobState = Literal["queued", "running", "completed", "failed"]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class ScanJob:
    scan_id: str
    request: ScanRequest
    status: JobState = "queued"
    submitted_at: str = field(default_factory=utc_now_iso)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None
    result: Optional[ScanResponse] = None


class JobManager:
    def __init__(self, max_workers: int = 3) -> None:
        self._jobs: Dict[str, ScanJob] = {}
        self._lock = Lock()
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="nmap-scan")

    def submit_scan(self, req: ScanRequest) -> ScanJobStatusResponse:
        job = ScanJob(scan_id=str(uuid4()), request=req)
        with self._lock:
            self._jobs[job.scan_id] = job

        self._executor.submit(self._run_job, job.scan_id)
        return self.get_job(job.scan_id, include_result=False)

    def get_job(self, scan_id: str, include_result: bool = True) -> ScanJobStatusResponse:
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                raise KeyError(scan_id)

            return ScanJobStatusResponse(
                scan_id=job.scan_id,
                status=job.status,
                submitted_at=job.submitted_at,
                started_at=job.started_at,
                completed_at=job.completed_at,
                error=job.error,
                result=job.result if include_result and job.status == "completed" else None,
            )

    def _run_job(self, scan_id: str) -> None:
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                return
            job.status = "running"
            job.started_at = utc_now_iso()
            req = job.request

        try:
            result = scan_domain(
                domain=req.domain.strip(),
                full_port_scan=req.full_port_scan,
                udp_scan=req.udp_scan,
                response_profile=req.response_profile,
            )
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                job = self._jobs.get(scan_id)
                if job is None:
                    return
                job.status = "failed"
                job.error = str(exc)
                job.completed_at = utc_now_iso()
            return

        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                return
            job.status = "completed"
            job.result = result
            job.completed_at = utc_now_iso()


job_manager = JobManager()

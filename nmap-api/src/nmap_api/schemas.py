from __future__ import annotations

from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    domain: str = Field(..., description="Target domain name")
    full_port_scan: bool = Field(
        default=False,
        description="If true, scan all ports for selected protocols. If false, use top ports.",
    )
    udp_scan: bool = Field(
        default=False,
        description="If true, include UDP scanning. Default false (TCP-only).",
    )
    response_profile: Literal["full", "concise"] = Field(
        default="full",
        description="Response verbosity profile. 'concise' trims heavy evidence fields.",
    )


class OpenPortInfo(BaseModel):
    port: int
    protocol: str
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None


class VulnerabilityFinding(BaseModel):
    name: str
    vulnerable: bool
    evidence: str


class CertificateIssue(BaseModel):
    issue: str
    detected: bool
    evidence: str


class SecurityHeadersResult(BaseModel):
    checked_url: Optional[str] = None
    present: Dict[str, str] = Field(default_factory=dict)
    missing: List[str] = Field(default_factory=list)
    score: int


class ComplianceResult(BaseModel):
    standard: str
    pass_check: bool
    notes: List[str] = Field(default_factory=list)


class PQCSafetyIntel(BaseModel):
    certificate_key_algorithm: Optional[str] = None
    certificate_key_size_bits: Optional[int] = None
    quantum_break_risk: str
    pfs_detected: bool
    pqc_ready_now: bool
    recommendations: List[str] = Field(default_factory=list)


class CertificateChainIntel(BaseModel):
    chain_depth_estimate: Optional[int] = None
    chain_complete_confidence: Literal["high", "medium", "low"]
    chain_complete_reason: str
    ocsp_urls: List[str] = Field(default_factory=list)
    ca_issuers_urls: List[str] = Field(default_factory=list)
    sct_present: Optional[bool] = None


class SecurityGrading(BaseModel):
    numeric_score: int
    letter_grade: str
    reasons: List[str] = Field(default_factory=list)


class NormalizedFinding(BaseModel):
    finding_id: str
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: Literal["high", "medium", "low"]
    status: Literal["open", "monitor", "resolved"] = "open"
    evidence: List[str] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list)
    why_it_matters: str
    remediation: str
    references: List[str] = Field(default_factory=list)


class RecommendationItem(BaseModel):
    priority: Literal["p0", "p1", "p2", "p3"]
    title: str
    action: str
    rationale: str


class PQCScoreCard(BaseModel):
    pqc_score: int
    pqc_grade: str
    dimensions: Dict[str, int] = Field(default_factory=dict)
    top_risks: List[str] = Field(default_factory=list)


class IntelligenceSummary(BaseModel):
    overall_risk: Literal["critical", "high", "medium", "low"]
    critical_findings: int
    high_findings: int
    top_actions: List[str] = Field(default_factory=list)


class ScanResponse(BaseModel):
    domain: str
    response_profile: Literal["full", "concise"] = "full"
    resolved_ip: Optional[str] = None
    open_ports: List[OpenPortInfo] = Field(default_factory=list)
    supported_tls_versions: List[str] = Field(default_factory=list)
    tls_key_exchange_algorithms: List[str] = Field(default_factory=list)
    tls_encryption_algorithms: List[str] = Field(default_factory=list)
    tls_signature_algorithms: List[str] = Field(default_factory=list)
    supported_cipher_suites: Dict[str, List[str]] = Field(default_factory=dict)
    supported_cipher_grades: Dict[str, Dict[str, str]] = Field(default_factory=dict)
    vulnerabilities: List[VulnerabilityFinding] = Field(default_factory=list)
    certificate_chain_issues: List[CertificateIssue] = Field(default_factory=list)
    security_headers: SecurityHeadersResult
    compliance: List[ComplianceResult] = Field(default_factory=list)
    pqc_safety_intelligence: PQCSafetyIntel
    certificate_chain_intelligence: CertificateChainIntel
    security_grade: SecurityGrading
    findings: List[NormalizedFinding] = Field(default_factory=list)
    recommendations: List[RecommendationItem] = Field(default_factory=list)
    pqc_scorecard: PQCScoreCard
    intelligence_summary: IntelligenceSummary
    raw_nmap_command: str
    scan_notes: List[str] = Field(default_factory=list)


class ScanJobCreateResponse(BaseModel):
    scan_id: str
    status: Literal["queued", "running", "completed", "failed"]


class ScanJobStatusResponse(BaseModel):
    scan_id: str
    status: Literal["queued", "running", "completed", "failed"]
    submitted_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None
    result: Optional[ScanResponse] = None


class EthicalScanRequest(BaseModel):
    target: str = Field(..., description="Target domain or IPv4 address")
    include_tls_version_tests: bool = Field(
        default=True,
        description="If true, probe TLS 1.0/1.1/1.2/1.3 support with focused checks.",
    )
    user_agent: str = Field(
        default="PQCSecurityScanner/1.0 (+https://example.com/scanner-info; security@example.com)",
        description="Custom user-agent supplied to compatible NSE scripts.",
    )


class SSHHostKeyInfo(BaseModel):
    algorithm: str
    key_size_bits: Optional[int] = None
    fingerprint: Optional[str] = None


class SSHIntelligence(BaseModel):
    kex_algorithms: List[str] = Field(default_factory=list)
    host_key_algorithms: List[str] = Field(default_factory=list)
    encryption_algorithms: List[str] = Field(default_factory=list)
    mac_algorithms: List[str] = Field(default_factory=list)
    host_keys: List[SSHHostKeyInfo] = Field(default_factory=list)


class TLSVersionProbeResult(BaseModel):
    tls_version: str
    supported: bool
    evidence: str


class EthicalScanResponse(BaseModel):
    target: str
    resolved_ip: Optional[str] = None
    open_ports: List[OpenPortInfo] = Field(default_factory=list)
    ssh_found: bool = False
    supported_tls_versions: List[str] = Field(default_factory=list)
    tls_key_exchange_algorithms: List[str] = Field(default_factory=list)
    tls_encryption_algorithms: List[str] = Field(default_factory=list)
    tls_signature_algorithms: List[str] = Field(default_factory=list)
    supported_cipher_suites: Dict[str, List[str]] = Field(default_factory=dict)
    supported_cipher_grades: Dict[str, Dict[str, str]] = Field(default_factory=dict)
    tls_version_probes: List[TLSVersionProbeResult] = Field(default_factory=list)
    pqc_safety_intelligence: PQCSafetyIntel
    certificate_chain_intelligence: CertificateChainIntel
    certificate_chain_issues: List[CertificateIssue] = Field(default_factory=list)
    ssh_intelligence: SSHIntelligence
    scan_notes: List[str] = Field(default_factory=list)
    raw_nmap_commands: List[str] = Field(default_factory=list)

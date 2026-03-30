from __future__ import annotations

import re
from typing import Dict, List

import requests

from .nmap_runner import NmapScanData
from .schemas import (
    CertificateIssue,
    CertificateChainIntel,
    ComplianceResult,
    IntelligenceSummary,
    NormalizedFinding,
    OpenPortInfo,
    PQCSafetyIntel,
    PQCScoreCard,
    RecommendationItem,
    ScanResponse,
    SecurityGrading,
    SecurityHeadersResult,
    VulnerabilityFinding,
)

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]


def build_response(domain: str, scan: NmapScanData) -> ScanResponse:
    vulnerabilities = detect_vulnerabilities(scan)
    cert_issues, key_algo, key_size = detect_certificate_chain_issues(scan.script_outputs)
    chain_intel = extract_certificate_chain_intelligence(scan.script_outputs)
    headers = analyze_security_headers(domain)
    compliance = evaluate_compliance(scan.tls_versions, scan.tls_ciphers, headers)
    pqc = pqc_intelligence(scan.tls_ciphers, key_algo, key_size)
    grade = grade_security(scan, vulnerabilities, cert_issues, headers, compliance, pqc)
    findings = build_structured_findings(scan, vulnerabilities, cert_issues, headers, compliance, pqc)
    recommendations = build_recommendations(findings, pqc)
    pqc_scorecard = build_pqc_scorecard(scan, cert_issues, vulnerabilities, compliance, headers, pqc)
    summary = build_intelligence_summary(findings, recommendations)

    notes: List[str] = []
    if not scan.tls_versions:
        notes.append("No TLS endpoint data detected in scanned ports.")
    if not scan.open_ports:
        notes.append("No open ports detected by current nmap scan profile.")

    return ScanResponse(
        domain=domain,
        response_profile="full",
        resolved_ip=scan.resolved_ip,
        open_ports=[
            OpenPortInfo(
                port=int(p["port"]),
                protocol=p["protocol"],
                service=p["service"] or None,
                product=p["product"] or None,
                version=p["version"] or None,
                extra_info=p["extra_info"] or None,
            )
            for p in scan.open_ports
        ],
        supported_tls_versions=scan.tls_versions,
        supported_cipher_suites=scan.tls_ciphers,
        vulnerabilities=vulnerabilities,
        certificate_chain_issues=cert_issues,
        security_headers=headers,
        compliance=compliance,
        pqc_safety_intelligence=pqc,
        certificate_chain_intelligence=chain_intel,
        security_grade=grade,
        findings=findings,
        recommendations=recommendations,
        pqc_scorecard=pqc_scorecard,
        intelligence_summary=summary,
        raw_nmap_command=scan.command,
        scan_notes=notes,
    )


def detect_vulnerabilities(scan: NmapScanData) -> List[VulnerabilityFinding]:
    script_outputs = scan.script_outputs
    checks = [
        ("Heartbleed", "ssl-heartbleed"),
        ("POODLE", "ssl-poodle"),
        ("CCS Injection", "ssl-ccs-injection"),
        ("SSLv2 Support", "sslv2"),
        ("Weak DH Params", "ssl-dh-params"),
    ]

    findings: List[VulnerabilityFinding] = []
    for display, script_id in checks:
        output = script_outputs.get(script_id, "")
        lowered = output.lower()
        vulnerable = "vulnerable" in lowered or "sslv2" in lowered and "enabled" in lowered
        findings.append(
            VulnerabilityFinding(
                name=display,
                vulnerable=vulnerable,
                evidence=output[:600] if output else "No output from script.",
            )
        )

    flattened = " ".join(cipher for suites in scan.tls_ciphers.values() for cipher in suites).upper()
    has_3des = "3DES" in flattened or "DES-CBC3" in flattened
    has_dhe = any(token in flattened for token in ["DHE", "EDH"])
    has_weak_dh_signal = "WEAK" in script_outputs.get("ssl-dh-params", "").upper()
    has_legacy_tls = any(v in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"} for v in scan.tls_versions)
    has_cbc = "CBC" in flattened

    findings.append(
        VulnerabilityFinding(
            name="SWEET32",
            vulnerable=has_3des,
            evidence=(
                "Detected 3DES-class suites in advertised ciphers."
                if has_3des
                else "No 3DES suites detected in parsed cipher set."
            ),
        )
    )
    findings.append(
        VulnerabilityFinding(
            name="LOGJAM",
            vulnerable=has_dhe and has_weak_dh_signal,
            evidence=(
                script_outputs.get("ssl-dh-params", "No ssl-dh-params output.")[:600]
                if has_dhe
                else "No DHE-based suites detected."
            ),
        )
    )
    findings.append(
        VulnerabilityFinding(
            name="DROWN",
            vulnerable=any(f.name == "SSLv2 Support" and f.vulnerable for f in findings),
            evidence=script_outputs.get("sslv2", "No sslv2 output.")[:600],
        )
    )
    findings.append(
        VulnerabilityFinding(
            name="BEAST/Lucky13 Class Signal",
            vulnerable=has_legacy_tls and has_cbc,
            evidence=(
                "CBC suites with legacy TLS versions were detected."
                if has_legacy_tls and has_cbc
                else "No CBC+legacy TLS combination detected from current scan output."
            ),
        )
    )
    findings.append(
        VulnerabilityFinding(
            name="ROBOT Class Signal",
            vulnerable=("_RSA_" in flattened) and ("ECDHE" not in flattened) and ("DHE" not in flattened),
            evidence=(
                "RSA key-exchange dominant profile observed without forward secrecy suites."
                if ("_RSA_" in flattened) and ("ECDHE" not in flattened) and ("DHE" not in flattened)
                else "No strong RSA key-exchange dominance signal observed."
            ),
        )
    )
    return findings


def detect_certificate_chain_issues(script_outputs: Dict[str, str]) -> tuple[List[CertificateIssue], str | None, int | None]:
    output = script_outputs.get("ssl-cert", "")
    lowered = output.lower()

    issues = [
        ("self_signed", "self-signed" in lowered or "self signed" in lowered),
        ("missing_intermediate", "unable to get local issuer certificate" in lowered),
        ("expired", "not valid after" in lowered and "expired" in lowered),
        ("hostname_mismatch", "subject alt name" in lowered and "does not match" in lowered),
    ]

    key_algo = extract_cert_key_algorithm(output)
    key_size = extract_cert_key_size_bits(output)

    return [
        CertificateIssue(issue=name, detected=detected, evidence=output[:600] if output else "No ssl-cert output.")
        for name, detected in issues
    ], key_algo, key_size


def extract_certificate_chain_intelligence(script_outputs: Dict[str, str]) -> CertificateChainIntel:
    output = script_outputs.get("ssl-cert", "")
    lowered = output.lower()

    issuer_count = len(re.findall(r"(?im)^\s*Issuer:\s*", output))
    subject_count = len(re.findall(r"(?im)^\s*Subject:\s*", output))
    chain_depth = max(issuer_count, subject_count) if (issuer_count or subject_count) else None

    all_urls = set(re.findall(r"https?://[^\s,\)]+", output))
    ocsp_urls = sorted(url for url in all_urls if "ocsp" in url.lower())
    ca_urls = sorted(url for url in all_urls if any(token in url.lower() for token in ["issuer", "ca", "crt"]))

    sct_present: bool | None = None
    if output:
        sct_present = any(token in lowered for token in ["signed certificate timestamp", "certificate transparency", "sct"])

    if "unable to get local issuer certificate" in lowered:
        confidence = "low"
        reason = "Chain appears incomplete (issuer resolution warning detected)."
    elif chain_depth and chain_depth >= 2:
        confidence = "high"
        reason = "Multiple chain elements were observed in ssl-cert output."
    elif output:
        confidence = "medium"
        reason = "Certificate data found, but chain completeness cannot be strongly verified from current script output."
    else:
        confidence = "low"
        reason = "No ssl-cert output available to assess chain completeness."

    return CertificateChainIntel(
        chain_depth_estimate=chain_depth,
        chain_complete_confidence=confidence,
        chain_complete_reason=reason,
        ocsp_urls=ocsp_urls,
        ca_issuers_urls=ca_urls,
        sct_present=sct_present,
    )


def extract_cert_key_algorithm(output: str) -> str | None:
    patterns = [
        r"Public Key type:\s*([A-Za-z0-9._-]+)",
        r"Public key algorithm:\s*([A-Za-z0-9._-]+)",
        r"pubkey:\s*([A-Za-z0-9._-]+)",
        r"Algorithm:\s*([A-Za-z0-9._-]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, output, flags=re.IGNORECASE)
        if match:
            return match.group(1).upper()
    return None


def extract_cert_key_size_bits(output: str) -> int | None:
    patterns = [
        r"Public Key bits:\s*(\d+)",
        r"Public key size:\s*(\d+)",
        r"Public-Key:\s*\((\d+)\s*bit\)",
        r"pubkey:[^\n]*?(\d{3,5})\s*bits",
        r"key\s*size[^\n:]*:\s*(\d{3,5})",
    ]
    for pattern in patterns:
        match = re.search(pattern, output, flags=re.IGNORECASE)
        if match:
            return int(match.group(1))

    for line in output.splitlines():
        if "pubkey" in line.lower() or "public key" in line.lower():
            match = re.search(r"(\d{3,5})\s*bits", line, flags=re.IGNORECASE)
            if match:
                return int(match.group(1))
    return None


def analyze_security_headers(domain: str) -> SecurityHeadersResult:
    attempted = [f"https://{domain}", f"http://{domain}"]
    present: Dict[str, str] = {}
    checked_url = None

    for url in attempted:
        try:
            resp = requests.get(url, timeout=12, verify=False, allow_redirects=True)
            checked_url = resp.url
            header_map = {k.lower(): v for k, v in resp.headers.items()}
            for h in SECURITY_HEADERS:
                if h in header_map:
                    present[h] = header_map[h]
            break
        except requests.RequestException:
            continue

    missing = [h for h in SECURITY_HEADERS if h not in present]
    score = max(0, 100 - len(missing) * 12)

    return SecurityHeadersResult(checked_url=checked_url, present=present, missing=missing, score=score)


def evaluate_compliance(
    tls_versions: List[str], tls_ciphers: Dict[str, List[str]], headers: SecurityHeadersResult
) -> List[ComplianceResult]:
    flattened = " ".join(cipher for suites in tls_ciphers.values() for cipher in suites).upper()
    weak_cipher = any(token in flattened for token in ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"])

    has_old_tls = any(v in {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1"} for v in tls_versions)

    pci_notes: List[str] = []
    if has_old_tls:
        pci_notes.append("Legacy TLS/SSL versions detected; PCI DSS requires TLS 1.2+.")
    if weak_cipher:
        pci_notes.append("Weak cipher suites detected; PCI DSS disallows weak crypto.")

    hipaa_notes: List[str] = []
    if has_old_tls:
        hipaa_notes.append("Legacy TLS/SSL versions increase ePHI transit risk.")
    if headers.score < 50:
        hipaa_notes.append("Security headers posture is weak for web-facing endpoint hardening.")

    return [
        ComplianceResult(standard="PCI DSS", pass_check=len(pci_notes) == 0, notes=pci_notes),
        ComplianceResult(standard="HIPAA", pass_check=len(hipaa_notes) == 0, notes=hipaa_notes),
    ]


def pqc_intelligence(
    tls_ciphers: Dict[str, List[str]], key_algorithm: str | None, key_size: int | None
) -> PQCSafetyIntel:
    combined = " ".join(cipher for suites in tls_ciphers.values() for cipher in suites).upper()
    pfs_detected = any(token in combined for token in ["ECDHE", "DHE", "X25519"])

    risk = "medium"
    recommendations: List[str] = []

    if key_algorithm in {"RSA", "ECDSA", "EC"}:
        risk = "high"
        recommendations.append("Current public-key algorithms are vulnerable to cryptographically relevant quantum computers.")
    if key_size and key_size < 2048 and (key_algorithm or "").upper() == "RSA":
        recommendations.append("Upgrade RSA keys to at least 2048/3072 bits while planning PQ migration.")
    if not pfs_detected:
        recommendations.append("Enable Perfect Forward Secrecy (ECDHE/DHE suites) to reduce retrospective decryption risk.")

    recommendations.append("Track NIST PQC standards (ML-KEM/ML-DSA) and adopt hybrid TLS once your stack supports it.")

    return PQCSafetyIntel(
        certificate_key_algorithm=key_algorithm,
        certificate_key_size_bits=key_size,
        quantum_break_risk=risk,
        pfs_detected=pfs_detected,
        pqc_ready_now=False,
        recommendations=recommendations,
    )


def grade_security(
    scan: NmapScanData,
    vulnerabilities: List[VulnerabilityFinding],
    cert_issues: List[CertificateIssue],
    headers: SecurityHeadersResult,
    compliance: List[ComplianceResult],
    pqc: PQCSafetyIntel,
) -> SecurityGrading:
    score = 100
    reasons: List[str] = []

    vuln_count = sum(1 for v in vulnerabilities if v.vulnerable)
    if vuln_count:
        penalty = min(40, vuln_count * 12)
        score -= penalty
        reasons.append(f"Detected {vuln_count} vulnerability indicators from Nmap scripts (-{penalty}).")

    if any(v in {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1"} for v in scan.tls_versions):
        score -= 20
        reasons.append("Legacy TLS/SSL support present (-20).")

    weak_cipher = any(
        any(token in cipher.upper() for token in ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"])
        for suites in scan.tls_ciphers.values()
        for cipher in suites
    )
    if weak_cipher:
        score -= 15
        reasons.append("Weak cipher suites detected (-15).")

    issue_count = sum(1 for i in cert_issues if i.detected)
    if issue_count:
        penalty = min(15, issue_count * 5)
        score -= penalty
        reasons.append(f"Certificate chain/validity issues detected (-{penalty}).")

    if headers.score < 70:
        score -= 10
        reasons.append("Insufficient security headers posture (-10).")

    failed_compliance = [c.standard for c in compliance if not c.pass_check]
    if failed_compliance:
        score -= 10
        reasons.append(f"Compliance checks failed: {', '.join(failed_compliance)} (-10).")

    if pqc.quantum_break_risk == "high":
        score -= 5
        reasons.append("High long-term quantum break risk for classical public-key algorithms (-5).")

    score = max(0, min(100, score))
    grade = numeric_to_grade(score)

    if not reasons:
        reasons.append("No critical issues detected by current scan scope.")

    return SecurityGrading(numeric_score=score, letter_grade=grade, reasons=reasons)


def numeric_to_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def build_structured_findings(
    scan: NmapScanData,
    vulnerabilities: List[VulnerabilityFinding],
    cert_issues: List[CertificateIssue],
    headers: SecurityHeadersResult,
    compliance: List[ComplianceResult],
    pqc: PQCSafetyIntel,
) -> List[NormalizedFinding]:
    findings: List[NormalizedFinding] = []
    assets = [f"{p['protocol']}/{p['port']}" for p in scan.open_ports]

    for vuln in vulnerabilities:
        if not vuln.vulnerable:
            continue
        fid = f"vuln_{vuln.name.lower().replace(' ', '_')}"
        severity = "high" if vuln.name in {"Heartbleed", "POODLE", "CCS Injection"} else "medium"
        findings.append(
            NormalizedFinding(
                finding_id=fid,
                title=f"{vuln.name} indicator detected",
                severity=severity,
                confidence="medium",
                evidence=[vuln.evidence],
                affected_assets=assets,
                why_it_matters="Known SSL/TLS weaknesses increase compromise and traffic decryption risk.",
                remediation="Disable affected legacy options and patch/upgrade the TLS stack.",
                references=["https://nmap.org/nsedoc/"]
            )
        )

    has_legacy_tls = any(v in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"} for v in scan.tls_versions)
    if has_legacy_tls:
        findings.append(
            NormalizedFinding(
                finding_id="tls_legacy_versions",
                title="Legacy TLS/SSL versions enabled",
                severity="high",
                confidence="high",
                evidence=[", ".join(scan.tls_versions)],
                affected_assets=assets,
                why_it_matters="Legacy protocol versions are deprecated and expose downgrade/known-protocol risks.",
                remediation="Disable SSLv2/SSLv3/TLSv1.0/TLSv1.1 and enforce TLSv1.2+.",
                references=["https://owasp.org/www-project-transport-layer-protection/"]
            )
        )

    weak_ciphers = sorted(
        {
            cipher
            for suites in scan.tls_ciphers.values()
            for cipher in suites
            if any(token in cipher.upper() for token in ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"])
        }
    )
    if weak_ciphers:
        findings.append(
            NormalizedFinding(
                finding_id="tls_weak_cipher_suites",
                title="Weak cipher suites detected",
                severity="high",
                confidence="high",
                evidence=weak_ciphers[:20],
                affected_assets=assets,
                why_it_matters="Weak ciphers reduce confidentiality and can be practically attacked.",
                remediation="Remove weak ciphers and prefer modern AEAD suites with forward secrecy.",
                references=["https://wiki.mozilla.org/Security/Server_Side_TLS"]
            )
        )

    for issue in cert_issues:
        if not issue.detected:
            continue
        findings.append(
            NormalizedFinding(
                finding_id=f"cert_{issue.issue}",
                title=f"Certificate issue: {issue.issue}",
                severity="medium",
                confidence="medium",
                evidence=[issue.evidence],
                affected_assets=assets,
                why_it_matters="Certificate chain or identity issues can break trust and facilitate interception.",
                remediation="Fix certificate chain completeness/validity and verify hostname coverage.",
                references=["https://www.rfc-editor.org/rfc/rfc5280"]
            )
        )

    if headers.missing:
        findings.append(
            NormalizedFinding(
                finding_id="http_security_headers_missing",
                title="Security headers are incomplete",
                severity="medium" if len(headers.missing) >= 3 else "low",
                confidence="high",
                evidence=headers.missing,
                affected_assets=[headers.checked_url] if headers.checked_url else assets,
                why_it_matters="Missing hardening headers increase exposure to client-side attack classes.",
                remediation="Implement strict-transport-security, CSP, frame and MIME protections.",
                references=["https://owasp.org/www-project-secure-headers/"]
            )
        )

    for c in compliance:
        if c.pass_check:
            continue
        findings.append(
            NormalizedFinding(
                finding_id=f"compliance_{c.standard.lower().replace(' ', '_')}",
                title=f"{c.standard} compliance check failed",
                severity="high",
                confidence="medium",
                evidence=c.notes,
                affected_assets=assets,
                why_it_matters="Compliance drift often correlates with exploitable controls gaps.",
                remediation="Address failed controls and retest until policy baselines pass.",
                references=[]
            )
        )

    if pqc.quantum_break_risk == "high":
        findings.append(
            NormalizedFinding(
                finding_id="pqc_classical_dependency",
                title="High long-term quantum break exposure",
                severity="medium",
                confidence="high",
                evidence=[
                    f"Key algorithm: {pqc.certificate_key_algorithm}",
                    f"Key size: {pqc.certificate_key_size_bits}",
                ],
                affected_assets=assets,
                why_it_matters="Classical public-key algorithms are expected to be vulnerable to CRQC-era attacks.",
                remediation="Prepare hybrid TLS and crypto-agile certificate/key lifecycle processes.",
                references=["https://csrc.nist.gov/projects/post-quantum-cryptography"]
            )
        )

    return findings


def build_recommendations(findings: List[NormalizedFinding], pqc: PQCSafetyIntel) -> List[RecommendationItem]:
    priorities = {
        "tls_legacy_versions": RecommendationItem(
            priority="p0",
            title="Disable legacy TLS protocols",
            action="Enforce TLS 1.2+ and remove SSLv2/SSLv3/TLSv1.0/TLSv1.1 across all internet-facing services.",
            rationale="Eliminates high-probability downgrade and known-protocol attack surface.",
        ),
        "tls_weak_cipher_suites": RecommendationItem(
            priority="p0",
            title="Remove weak cipher suites",
            action="Disable RC4/DES/3DES/MD5/NULL/EXPORT suites and keep modern AEAD + PFS suites only.",
            rationale="Improves confidentiality and integrity guarantees under active attack.",
        ),
        "http_security_headers_missing": RecommendationItem(
            priority="p2",
            title="Harden HTTP security headers",
            action="Add HSTS, CSP, X-Content-Type-Options, X-Frame-Options and Referrer-Policy.",
            rationale="Reduces browser-side exploitation and hardens web delivery posture.",
        ),
        "pqc_classical_dependency": RecommendationItem(
            priority="p1",
            title="Start PQC migration plan",
            action="Introduce crypto-agility controls and pilot hybrid key exchange in pre-production.",
            rationale="Reduces long-term harvest-now-decrypt-later exposure.",
        ),
    }

    recs: List[RecommendationItem] = []
    seen = set()
    for finding in findings:
        if finding.finding_id in priorities and finding.finding_id not in seen:
            recs.append(priorities[finding.finding_id])
            seen.add(finding.finding_id)

    if pqc.recommendations and "pqc_classical_dependency" not in seen:
        recs.append(
            RecommendationItem(
                priority="p2",
                title="Track and operationalize PQC standards",
                action=pqc.recommendations[0],
                rationale="Builds readiness before ecosystem-wide mandatory migration pressure.",
            )
        )

    if not recs:
        recs.append(
            RecommendationItem(
                priority="p3",
                title="Maintain secure baseline",
                action="Continue periodic scans and regression monitoring.",
                rationale="Preserves current posture and catches future drift early.",
            )
        )

    order = {"p0": 0, "p1": 1, "p2": 2, "p3": 3}
    return sorted(recs, key=lambda r: order[r.priority])


def build_pqc_scorecard(
    scan: NmapScanData,
    cert_issues: List[CertificateIssue],
    vulnerabilities: List[VulnerabilityFinding],
    compliance: List[ComplianceResult],
    headers: SecurityHeadersResult,
    pqc: PQCSafetyIntel,
) -> PQCScoreCard:
    legacy_tls = any(v in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"} for v in scan.tls_versions)
    vuln_count = sum(1 for v in vulnerabilities if v.vulnerable)
    cert_issue_count = sum(1 for i in cert_issues if i.detected)
    compliance_fails = sum(1 for c in compliance if not c.pass_check)

    crypto_agility = 100
    if legacy_tls:
        crypto_agility -= 40
    if not pqc.pfs_detected:
        crypto_agility -= 20
    if pqc.quantum_break_risk == "high":
        crypto_agility -= 20

    classical_fragility = 100
    if pqc.quantum_break_risk == "high":
        classical_fragility -= 55
    if (pqc.certificate_key_algorithm or "").upper() == "RSA" and (pqc.certificate_key_size_bits or 0) < 3072:
        classical_fragility -= 15

    chain_modernization = max(0, 100 - cert_issue_count * 20)
    protocol_hardening = max(0, 100 - vuln_count * 15)
    operational_readiness = max(0, 100 - compliance_fails * 20 - max(0, 70 - headers.score) // 2)

    dims = {
        "crypto_agility": max(0, min(100, crypto_agility)),
        "classical_fragility": max(0, min(100, classical_fragility)),
        "chain_modernization": max(0, min(100, chain_modernization)),
        "protocol_hardening": max(0, min(100, protocol_hardening)),
        "operational_readiness": max(0, min(100, operational_readiness)),
    }
    score = round(sum(dims.values()) / len(dims))
    grade = numeric_to_grade(score)

    risks: List[str] = []
    if legacy_tls:
        risks.append("Legacy TLS versions remain enabled")
    if vuln_count:
        risks.append(f"{vuln_count} vulnerability indicators detected")
    if pqc.quantum_break_risk == "high":
        risks.append("Classical public-key dependency carries high CRQC-era risk")
    if cert_issue_count:
        risks.append("Certificate chain and trust issues were detected")
    if compliance_fails:
        risks.append("Regulatory control checks failed")

    return PQCScoreCard(pqc_score=score, pqc_grade=grade, dimensions=dims, top_risks=risks[:5])


def build_intelligence_summary(
    findings: List[NormalizedFinding], recommendations: List[RecommendationItem]
) -> IntelligenceSummary:
    critical = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")

    if critical > 0:
        risk = "critical"
    elif high > 0:
        risk = "high"
    elif findings:
        risk = "medium"
    else:
        risk = "low"

    return IntelligenceSummary(
        overall_risk=risk,
        critical_findings=critical,
        high_findings=high,
        top_actions=[r.title for r in recommendations[:3]],
    )


def apply_response_profile(resp: ScanResponse, profile: str) -> ScanResponse:
    if profile == "full":
        resp.response_profile = "full"
        return resp

    resp.response_profile = "concise"

    for v in resp.vulnerabilities:
        if len(v.evidence) > 220:
            v.evidence = v.evidence[:220] + "..."

    for c in resp.certificate_chain_issues:
        if len(c.evidence) > 220:
            c.evidence = c.evidence[:220] + "..."

    for f in resp.findings:
        if f.evidence:
            f.evidence = [e[:220] + "..." if len(e) > 220 else e for e in f.evidence[:2]]

    for version, suites in list(resp.supported_cipher_suites.items()):
        if len(suites) > 20:
            resp.supported_cipher_suites[version] = suites[:20] + [f"... truncated {len(suites) - 20} suites"]

    resp.scan_notes.append("Concise response profile enabled: evidence and large lists truncated.")
    return resp

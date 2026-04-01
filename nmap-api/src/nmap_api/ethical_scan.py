from __future__ import annotations

import ipaddress
import re
import shlex
import shutil
import socket
import subprocess
from typing import Dict, List

from fastapi import HTTPException

from .analysis import (
    detect_certificate_chain_issues,
    extract_certificate_chain_intelligence,
    extract_tls_encryption_algorithms,
    extract_tls_kex_algorithms,
    extract_tls_signature_algorithms,
    pqc_intelligence,
)
from .nmap_runner import NmapScanData, merge_scan_data, parse_nmap_xml
from .schemas import (
    CertificateIssue,
    EthicalScanRequest,
    EthicalScanResponse,
    OpenPortInfo,
    SSHHostKeyInfo,
    SSHIntelligence,
    TLSVersionProbeResult,
)

ETHICAL_SCRIPTS = [
    "ssl-cert",
    "ssl-enum-ciphers",
    "ssl-dh-params",
    "ssh2-enum-algos",
    "ssh-hostkey",
]

TLS_VERSION_MAP = {
    "1.0": "TLSv1.0",
    "1.1": "TLSv1.1",
    "1.2": "TLSv1.2",
    "1.3": "TLSv1.3",
}


def ethical_scan(req: EthicalScanRequest) -> EthicalScanResponse:
    target = req.target.strip()
    validate_target(target)

    if shutil.which("nmap") is None:
        raise HTTPException(status_code=500, detail="nmap is not installed or not in PATH")

    user_agent_arg = f"http.useragent={req.user_agent.strip()}"
    base_cmd = [
        "nmap",
        "-Pn",
        "-sT",
        "-p",
        "443,22",
        "--script",
        ",".join(ETHICAL_SCRIPTS),
        "--script-args",
        user_agent_arg,
        "-T2",
        "--max-rate",
        "10",
        "--scan-delay",
        "1s",
        "-oX",
        "-",
        target,
    ]

    commands_run: List[str] = []

    base_scan = run_nmap_xml_command(base_cmd)
    commands_run.append(shlex.join(base_cmd))

    version_probe_results: List[TLSVersionProbeResult] = []
    version_scan = NmapScanData(
        command="",
        resolved_ip=None,
        open_ports=[],
        tls_versions=[],
        tls_ciphers={},
        tls_cipher_grades={},
        script_outputs={},
    )

    if req.include_tls_version_tests:
        for tls_version, display in TLS_VERSION_MAP.items():
            probe_cmd = [
                "nmap",
                "-Pn",
                "-sT",
                "-p",
                "443",
                "--script",
                "ssl-enum-ciphers",
                "--script-args",
                f"tls.version={tls_version},{user_agent_arg}",
                "-T2",
                "--max-rate",
                "10",
                "--scan-delay",
                "1s",
                "-oX",
                "-",
                target,
            ]
            commands_run.append(shlex.join(probe_cmd))
            try:
                probe_scan = run_nmap_xml_command(probe_cmd)
            except HTTPException as exc:
                version_probe_results.append(
                    TLSVersionProbeResult(
                        tls_version=display,
                        supported=False,
                        evidence=f"Probe failed: {exc.detail}",
                    )
                )
                continue

            version_scan = merge_scan_data(version_scan, probe_scan)
            supported = display in probe_scan.tls_versions
            evidence = "Version detected in ssl-enum-ciphers output." if supported else "Version not detected in probe output."
            version_probe_results.append(TLSVersionProbeResult(tls_version=display, supported=supported, evidence=evidence))

    merged_scan = merge_scan_data(base_scan, version_scan)

    cert_issues, key_algo, key_size = detect_certificate_chain_issues(merged_scan.script_outputs)
    cert_chain = extract_certificate_chain_intelligence(merged_scan.script_outputs)
    pqc = pqc_intelligence(merged_scan.tls_ciphers, key_algo, key_size)
    ssh_intel = parse_ssh_intelligence(merged_scan.script_outputs)
    ssh_found = has_ssh_signal(merged_scan, ssh_intel)

    notes: List[str] = []
    if not merged_scan.open_ports:
        notes.append("No open ports detected on 22/443 with the ethical profile.")
    if not merged_scan.tls_versions:
        notes.append("No TLS versions detected. Port 443 may be closed or not serving TLS.")
    if not merged_scan.script_outputs.get("ssl-cert", "").strip():
        notes.append("No ssl-cert script output captured for certificate-chain analysis.")
    if not merged_scan.script_outputs.get("ssh2-enum-algos", "").strip():
        notes.append("No ssh2-enum-algos script output captured for SSH algorithm analysis.")

    return EthicalScanResponse(
        target=target,
        resolved_ip=merged_scan.resolved_ip,
        open_ports=[
            OpenPortInfo(
                port=int(p["port"]),
                protocol=p["protocol"],
                service=p["service"] or None,
                product=p["product"] or None,
                version=p["version"] or None,
                extra_info=p["extra_info"] or None,
            )
            for p in merged_scan.open_ports
        ],
        ssh_found=ssh_found,
        supported_tls_versions=merged_scan.tls_versions,
        tls_key_exchange_algorithms=extract_tls_kex_algorithms(merged_scan.tls_ciphers),
        tls_encryption_algorithms=extract_tls_encryption_algorithms(merged_scan.tls_ciphers),
        tls_signature_algorithms=extract_tls_signature_algorithms(
            merged_scan.tls_ciphers,
            merged_scan.script_outputs,
        ),
        supported_cipher_suites=merged_scan.tls_ciphers,
        supported_cipher_grades=merged_scan.tls_cipher_grades,
        tls_version_probes=version_probe_results,
        pqc_safety_intelligence=pqc,
        certificate_chain_intelligence=cert_chain,
        certificate_chain_issues=normalize_cert_issues(cert_issues),
        ssh_intelligence=ssh_intel,
        scan_notes=notes,
        raw_nmap_commands=commands_run,
    )


def validate_target(target: str) -> None:
    if not target or "://" in target:
        raise HTTPException(status_code=400, detail="Provide a bare domain or IP, e.g., example.com or 93.184.216.34")

    try:
        ipaddress.ip_address(target)
        return
    except ValueError:
        pass

    try:
        socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise HTTPException(status_code=400, detail=f"DNS resolution failed: {exc}") from exc


def run_nmap_xml_command(cmd: List[str]) -> NmapScanData:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail=f"nmap timed out: {shlex.join(cmd)}") from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to execute nmap: {exc}") from exc

    if proc.returncode != 0:
        msg = proc.stderr.strip() or proc.stdout.strip() or "unknown nmap error"
        raise HTTPException(status_code=500, detail=f"nmap failed: {msg}")

    try:
        return parse_nmap_xml(cmd, proc.stdout)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Failed to parse nmap XML output: {exc}") from exc


def parse_ssh_intelligence(script_outputs: Dict[str, str]) -> SSHIntelligence:
    enum_out = script_outputs.get("ssh2-enum-algos", "")
    hostkey_out = script_outputs.get("ssh-hostkey", "")

    sections = {
        "kex_algorithms": set(),
        "server_host_key_algorithms": set(),
        "encryption_algorithms": set(),
        "mac_algorithms": set(),
    }

    current: str | None = None
    for raw in enum_out.splitlines():
        line = raw.strip()
        if not line:
            continue

        if line.endswith(":"):
            key = line[:-1].strip().lower()
            current = key if key in sections else None
            continue

        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            if key in sections and value:
                for item in split_algo_items(value):
                    sections[key].add(item)
                current = key
                continue

        if current in sections:
            for item in split_algo_items(line):
                sections[current].add(item)

    host_keys = parse_ssh_host_keys(hostkey_out)

    host_key_algorithms = set(sections["server_host_key_algorithms"])
    host_key_algorithms.update(key.algorithm for key in host_keys)

    return SSHIntelligence(
        kex_algorithms=sorted(sections["kex_algorithms"]),
        host_key_algorithms=sorted(host_key_algorithms),
        encryption_algorithms=sorted(sections["encryption_algorithms"]),
        mac_algorithms=sorted(sections["mac_algorithms"]),
        host_keys=host_keys,
    )


def parse_ssh_host_keys(hostkey_output: str) -> List[SSHHostKeyInfo]:
    keys: List[SSHHostKeyInfo] = []
    seen: set[tuple[str, int | None, str | None]] = set()

    for raw in hostkey_output.splitlines():
        line = raw.strip()
        if not line:
            continue

        lowered = line.lower()
        algorithm = None
        if "ssh-rsa" in lowered or " rsa " in f" {lowered} ":
            algorithm = "ssh-rsa"
        elif "ecdsa" in lowered:
            algorithm = "ecdsa-sha2"
        elif "ed25519" in lowered:
            algorithm = "ssh-ed25519"

        if algorithm is None:
            continue

        key_bits = None
        bits_match = None
        for pattern in [r"\b(\d{3,5})\b", r"\((\d{3,5})\)"]:
            bits_match = re.search(pattern, line)
            if bits_match:
                key_bits = int(bits_match.group(1))
                break

        fingerprint = None
        if " " in line:
            tokens = [t for t in line.split() if t]
            for token in tokens:
                if token.count(":") >= 4 or token.startswith("SHA256:"):
                    fingerprint = token
                    break

        sig = (algorithm, key_bits, fingerprint)
        if sig in seen:
            continue
        seen.add(sig)
        keys.append(SSHHostKeyInfo(algorithm=algorithm, key_size_bits=key_bits, fingerprint=fingerprint))

    return keys


def split_algo_items(value: str) -> List[str]:
    if not value:
        return []
    if "," in value:
        return [item.strip() for item in value.split(",") if item.strip()]
    return [value.strip()]


def normalize_cert_issues(items: List[CertificateIssue]) -> List[CertificateIssue]:
    deduped: Dict[str, CertificateIssue] = {}
    for item in items:
        deduped[item.issue] = item
    return list(deduped.values())


def has_ssh_signal(scan: NmapScanData, ssh_intel: SSHIntelligence) -> bool:
    if any(p.get("port") == "22" and p.get("protocol") == "tcp" for p in scan.open_ports):
        return True

    if any(p.get("service", "").lower() == "ssh" for p in scan.open_ports):
        return True

    if scan.script_outputs.get("ssh2-enum-algos", "").strip() or scan.script_outputs.get("ssh-hostkey", "").strip():
        return True

    if ssh_intel.kex_algorithms or ssh_intel.host_key_algorithms or ssh_intel.host_keys:
        return True

    return False

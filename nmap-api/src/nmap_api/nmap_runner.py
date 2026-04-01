from __future__ import annotations

import os
import re
import shutil
import shlex
import socket
import ssl
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, List, Tuple


SCRIPT_SET = [
    "ssl-enum-ciphers",
    "ssl-cert",
    "ssl-heartbleed",
    "ssl-poodle",
    "ssl-ccs-injection",
    "sslv2",
    "ssl-dh-params",
    "http-security-headers",
]

TLS_VERSION_ORDER = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
TLS_ENRICHMENT_PORTS = "443,8443,9443,10443,4443,5443"
TLS_ENRICHMENT_SCRIPTS = ["ssl-enum-ciphers", "ssl-cert"]


@dataclass
class NmapScanData:
    command: str
    resolved_ip: str | None
    open_ports: List[Dict[str, str]]
    tls_versions: List[str]
    tls_ciphers: Dict[str, List[str]]
    tls_cipher_grades: Dict[str, Dict[str, str]]
    script_outputs: Dict[str, str]


def build_nmap_command(domain: str, full_port_scan: bool, include_udp: bool) -> List[str]:
    has_root = is_root_user()
    base = ["nmap", "-Pn", "-sV", "--script", ",".join(SCRIPT_SET), "-oX", "-"]
    tcp_scan_mode = "-sS" if has_root else "-sT"

    if include_udp and has_root:
        if full_port_scan:
            # Full mode: all TCP + all UDP ports.
            base += [tcp_scan_mode, "-sU", "-p", "T:1-65535,U:1-65535"]
        else:
            # Normal mode: top TCP + top UDP ports.
            base += [tcp_scan_mode, "-sU", "--top-ports", "1000"]
    else:
        if full_port_scan:
            # Full mode TCP-only.
            base += [tcp_scan_mode, "-p-"]
        else:
            # Normal mode TCP-only.
            base += [tcp_scan_mode, "--top-ports", "1000"]

    base += [domain]
    return base


def run_nmap(domain: str, full_port_scan: bool, include_udp: bool) -> NmapScanData:
    cmd = build_nmap_command(domain, full_port_scan, include_udp)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        error_message = proc.stderr.strip() or proc.stdout.strip()
        if "requires root privileges" in error_message.lower():
            # Best-effort fallback to a fully unprivileged TCP connect scan.
            fallback_cmd = [
                "nmap",
                "-Pn",
                "-sV",
                "--script",
                ",".join(SCRIPT_SET),
                "-oX",
                "-",
                "-sT",
                "--top-ports",
                "1000",
                domain,
            ]
            fallback_proc = subprocess.run(fallback_cmd, capture_output=True, text=True)
            if fallback_proc.returncode == 0:
                primary = parse_nmap_xml(fallback_cmd, fallback_proc.stdout)
                return maybe_enrich_tls_data(domain, primary)

            fallback_error = fallback_proc.stderr.strip() or fallback_proc.stdout.strip()
            raise RuntimeError(
                "nmap failed with root-only scan type and unprivileged fallback failed: "
                f"{fallback_error or error_message}"
            )

        raise RuntimeError(f"nmap failed: {error_message}")

    primary = parse_nmap_xml(cmd, proc.stdout)
    enriched = maybe_enrich_tls_data(domain, primary)
    return maybe_enrich_tls_with_socket_probe(domain, enriched)


def is_root_user() -> bool:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    return geteuid() == 0


def parse_nmap_xml(cmd: List[str], xml_output: str) -> NmapScanData:
    root = ET.fromstring(xml_output)

    resolved_ip = None
    open_ports: List[Dict[str, str]] = []
    tls_versions: set[str] = set()
    tls_ciphers: Dict[str, set[str]] = {}
    tls_cipher_grades: Dict[str, Dict[str, str]] = {}
    script_outputs: Dict[str, str] = {}

    host = root.find("host")
    if host is not None:
        addr = host.find("address")
        if addr is not None:
            resolved_ip = addr.attrib.get("addr")

        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.attrib.get("state") != "open":
                    continue

                service_elem = port_elem.find("service")
                port_record = {
                    "port": port_elem.attrib.get("portid", "0"),
                    "protocol": port_elem.attrib.get("protocol", "tcp"),
                    "service": service_elem.attrib.get("name", "") if service_elem is not None else "",
                    "product": service_elem.attrib.get("product", "") if service_elem is not None else "",
                    "version": service_elem.attrib.get("version", "") if service_elem is not None else "",
                    "extra_info": service_elem.attrib.get("extrainfo", "") if service_elem is not None else "",
                }
                open_ports.append(port_record)

                for script in port_elem.findall("script"):
                    script_id = script.attrib.get("id", "")
                    script_output = collect_script_output(script)
                    if script_id:
                        existing = script_outputs.get(script_id, "")
                        joined = (existing + "\n" + script_output).strip() if existing else script_output
                        script_outputs[script_id] = joined

                    if script_id == "ssl-enum-ciphers":
                        versions, ciphers, grades = parse_ssl_enum_script(script, script_output)
                        tls_versions.update(versions)
                        for version, suites in ciphers.items():
                            tls_ciphers.setdefault(version, set()).update(suites)
                        merge_cipher_grades(tls_cipher_grades, grades)

        hostscript_elem = host.find("hostscript")
        if hostscript_elem is not None:
            for script in hostscript_elem.findall("script"):
                script_id = script.attrib.get("id", "")
                if not script_id:
                    continue

                script_output = collect_script_output(script)
                existing = script_outputs.get(script_id, "")
                joined = (existing + "\n" + script_output).strip() if existing else script_output
                script_outputs[script_id] = joined

                if script_id == "ssl-enum-ciphers":
                    versions, ciphers, grades = parse_ssl_enum_script(script, script_output)
                    tls_versions.update(versions)
                    for version, suites in ciphers.items():
                        tls_ciphers.setdefault(version, set()).update(suites)
                    merge_cipher_grades(tls_cipher_grades, grades)

    ordered_versions = sorted(tls_versions, key=tls_sort_key)
    ordered_ciphers = {k: sorted(v) for k, v in tls_ciphers.items()}
    ordered_grades = {version: dict(sorted(grades.items())) for version, grades in tls_cipher_grades.items()}

    return NmapScanData(
        command=shlex.join(cmd),
        resolved_ip=resolved_ip,
        open_ports=open_ports,
        tls_versions=ordered_versions,
        tls_ciphers=ordered_ciphers,
        tls_cipher_grades=ordered_grades,
        script_outputs=script_outputs,
    )


def parse_ssl_enum_script(
    script_elem: ET.Element, script_output: str = ""
) -> Tuple[List[str], Dict[str, List[str]], Dict[str, Dict[str, str]]]:
    versions: set[str] = set()
    ciphers: Dict[str, set[str]] = {}
    grades: Dict[str, Dict[str, str]] = {}

    output_text = script_output or script_elem.attrib.get("output", "")
    current_version = None
    for line in output_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.endswith(":") and ("TLS" in stripped or "SSL" in stripped):
            current_version = normalize_tls_version(stripped[:-1])
            versions.add(current_version)
            ciphers.setdefault(current_version, set())
            continue

        if current_version:
            for cipher in extract_ciphers_from_line(stripped):
                ciphers[current_version].add(cipher)
            grade_pairs = extract_cipher_grade_pairs_from_line(stripped)
            for cipher, grade in grade_pairs:
                grades.setdefault(current_version, {})[cipher] = grade

    # Parse all table nodes to handle nested NSE XML structures consistently.
    for table in script_elem.findall(".//table"):
        table_key = (table.attrib.get("key", "") or "").strip()
        if not table_key:
            continue

        if "TLS" in table_key or "SSL" in table_key:
            version = normalize_tls_version(table_key)
            versions.add(version)
            ciphers.setdefault(version, set())
            continue

    # Parent inference fallback for ElementTree: walk version tables and inspect descendants.
    for version_table in script_elem.findall(".//table"):
        version_key = (version_table.attrib.get("key", "") or "").strip()
        if not version_key or not ("TLS" in version_key or "SSL" in version_key):
            continue

        version = normalize_tls_version(version_key)
        versions.add(version)
        ciphers.setdefault(version, set())

        for subtable in version_table.findall(".//table"):
            cipher = extract_cipher_name(subtable)
            if cipher:
                ciphers[version].add(cipher)
                grade = extract_cipher_grade_from_table(subtable)
                if grade:
                    grades.setdefault(version, {})[cipher] = grade

        for elem in version_table.findall(".//elem"):
            text = (elem.text or "").strip()
            if not text:
                continue
            for cipher in extract_ciphers_from_line(text):
                ciphers[version].add(cipher)

    out = {
        version: sorted(suite for suite in suites if is_valid_cipher_suite(suite))
        for version, suites in ciphers.items()
    }
    out_grades: Dict[str, Dict[str, str]] = {}
    for version, suite_list in out.items():
        version_grades = grades.get(version, {})
        filtered = {suite: version_grades[suite] for suite in suite_list if suite in version_grades}
        if filtered:
            out_grades[version] = filtered

    return sorted(versions, key=tls_sort_key), out, out_grades


def maybe_enrich_tls_data(domain: str, scan: NmapScanData) -> NmapScanData:
    if scan.tls_versions and scan.script_outputs.get("ssl-cert", "").strip():
        return scan

    cmd = [
        "nmap",
        "-Pn",
        "-sT",
        "-sV",
        "--script",
        ",".join(TLS_ENRICHMENT_SCRIPTS),
        "-p",
        TLS_ENRICHMENT_PORTS,
        "-oX",
        "-",
        domain,
    ]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return scan

    tls_scan = parse_nmap_xml(cmd, proc.stdout)
    return merge_scan_data(scan, tls_scan)


def maybe_enrich_tls_with_socket_probe(domain: str, scan: NmapScanData) -> NmapScanData:
    if scan.tls_versions and scan.script_outputs.get("ssl-cert", "").strip():
        return scan

    probe = probe_tls_endpoint(domain, 443)
    if probe is None:
        return scan

    return merge_scan_data(scan, probe)


def merge_scan_data(primary: NmapScanData, extra: NmapScanData) -> NmapScanData:
    merged_ports: List[Dict[str, str]] = []
    seen_ports: set[tuple[str, str]] = set()
    for port in primary.open_ports + extra.open_ports:
        key = (port.get("protocol", ""), port.get("port", ""))
        if key in seen_ports:
            continue
        seen_ports.add(key)
        merged_ports.append(port)

    merged_versions = sorted(set(primary.tls_versions) | set(extra.tls_versions), key=tls_sort_key)

    merged_ciphers: Dict[str, List[str]] = {}
    for version in set(primary.tls_ciphers.keys()) | set(extra.tls_ciphers.keys()):
        merged_ciphers[version] = sorted(set(primary.tls_ciphers.get(version, [])) | set(extra.tls_ciphers.get(version, [])))

    merged_grades: Dict[str, Dict[str, str]] = {
        version: dict(grades)
        for version, grades in primary.tls_cipher_grades.items()
    }
    merge_cipher_grades(merged_grades, extra.tls_cipher_grades)

    merged_script_outputs = dict(primary.script_outputs)
    for script_id, output in extra.script_outputs.items():
        existing = merged_script_outputs.get(script_id, "")
        merged_script_outputs[script_id] = (existing + "\n" + output).strip() if existing else output

    command = primary.command
    if extra.command:
        command = f"{primary.command} ; {extra.command}"

    return NmapScanData(
        command=command,
        resolved_ip=primary.resolved_ip or extra.resolved_ip,
        open_ports=merged_ports,
        tls_versions=merged_versions,
        tls_ciphers=merged_ciphers,
        tls_cipher_grades=merged_grades,
        script_outputs=merged_script_outputs,
    )


def collect_script_output(script_elem: ET.Element) -> str:
    output_attr = (script_elem.attrib.get("output", "") or "").strip()
    lines: List[str] = []
    append_table_lines(script_elem, lines, indent=0)
    table_text = "\n".join(line for line in lines if line.strip()).strip()
    plain_text = "\n".join(segment.strip() for segment in script_elem.itertext() if segment and segment.strip())
    combined = "\n".join(part for part in [output_attr, table_text, plain_text] if part).strip()
    return dedupe_lines(combined)


def append_table_lines(node: ET.Element, lines: List[str], indent: int) -> None:
    prefix = " " * indent
    if node.tag == "table":
        key = node.attrib.get("key", "")
        if key:
            lines.append(f"{prefix}{key}:")
    elif node.tag == "elem":
        key = node.attrib.get("key", "")
        value = (node.text or "").strip()
        if key and value:
            lines.append(f"{prefix}{key}: {value}")
        elif value:
            lines.append(f"{prefix}{value}")

    for child in list(node):
        append_table_lines(child, lines, indent + 2)


def dedupe_lines(text: str) -> str:
    seen: set[str] = set()
    out_lines: List[str] = []
    for line in text.splitlines():
        normalized = line.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        out_lines.append(normalized)
    return "\n".join(out_lines)


def probe_tls_endpoint(domain: str, port: int) -> NmapScanData | None:
    version_candidates: List[tuple[str, ssl.TLSVersion]] = []
    for name, attr in [
        ("TLSv1.0", "TLSv1"),
        ("TLSv1.1", "TLSv1_1"),
        ("TLSv1.2", "TLSv1_2"),
        ("TLSv1.3", "TLSv1_3"),
    ]:
        value = getattr(ssl.TLSVersion, attr, None)
        if value is not None:
            version_candidates.append((name, value))

    if not version_candidates:
        return None

    discovered_versions: set[str] = set()
    discovered_ciphers: Dict[str, set[str]] = {}
    cert_output = ""

    for version_name, tls_version in version_candidates:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = tls_version
            context.maximum_version = tls_version

            with socket.create_connection((domain, port), timeout=8) as tcp_sock:
                with context.wrap_socket(tcp_sock, server_hostname=domain) as tls_sock:
                    discovered_versions.add(version_name)
                    cipher = tls_sock.cipher()
                    if cipher and cipher[0]:
                        discovered_ciphers.setdefault(version_name, set()).add(cipher[0])

                    if not cert_output:
                        der_cert = tls_sock.getpeercert(binary_form=True)
                        if der_cert:
                            pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
                            cert_output = render_certificate_text(pem_cert)
        except (OSError, ssl.SSLError, socket.timeout):
            continue

    if not discovered_versions and not cert_output:
        return None

    script_outputs: Dict[str, str] = {}
    if cert_output:
        script_outputs["ssl-cert"] = cert_output

    return NmapScanData(
        command=f"tls-socket-probe {domain}:{port}",
        resolved_ip=None,
        open_ports=[
            {
                "port": str(port),
                "protocol": "tcp",
                "service": "https",
                "product": "",
                "version": "",
                "extra_info": "",
            }
        ],
        tls_versions=sorted(discovered_versions, key=tls_sort_key),
        tls_ciphers={version: sorted(suites) for version, suites in discovered_ciphers.items()},
        tls_cipher_grades={},
        script_outputs=script_outputs,
    )


def render_certificate_text(pem_cert: str) -> str:
    if shutil.which("openssl") is None:
        return pem_cert.strip()

    try:
        proc = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-text"],
            input=pem_cert,
            capture_output=True,
            text=True,
            timeout=8,
        )
    except (OSError, subprocess.SubprocessError):
        return pem_cert.strip()

    if proc.returncode != 0:
        return pem_cert.strip()
    return proc.stdout.strip()


def extract_cipher_name(table_elem: ET.Element) -> str | None:
    table_key = (table_elem.attrib.get("key", "") or "").strip()
    if is_cipher_name(table_key):
        return table_key

    for elem in table_elem.findall("elem"):
        key = elem.attrib.get("key", "")
        if key == "name" and elem.text:
            return elem.text.strip()

        text = (elem.text or "").strip()
        if text:
            ciphers = extract_ciphers_from_line(text)
            if ciphers:
                return ciphers[0]
    return None


def extract_cipher_from_line(line: str) -> str | None:
    ciphers = extract_ciphers_from_line(line)
    if ciphers:
        return ciphers[0]
    return None


def extract_ciphers_from_line(line: str) -> List[str]:
    candidate = line.strip().rstrip(":")
    return re.findall(r"\b(?:TLS|SSL)_[A-Z0-9_\-]+\b", candidate)


def extract_cipher_grade_pairs_from_line(line: str) -> List[Tuple[str, str]]:
    # Typical ssl-enum-ciphers line examples:
    # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
    # TLS_RSA_WITH_AES_256_CBC_SHA - C
    pairs = re.findall(r"\b((?:TLS|SSL)_[A-Z0-9_\-]+)\b[^\n]*?-\s*([A-F])\b", line)
    return [(cipher, grade) for cipher, grade in pairs if is_valid_cipher_suite(cipher)]


def extract_cipher_grade_from_table(table_elem: ET.Element) -> str | None:
    for elem in table_elem.findall("elem"):
        key = (elem.attrib.get("key", "") or "").strip().lower()
        value = (elem.text or "").strip().upper()
        if key in {"strength", "grade"} and re.fullmatch(r"[A-F]", value):
            return value
    return None


def is_cipher_name(value: str) -> bool:
    return bool(re.match(r"^(TLS|SSL)_[A-Z0-9_\-]+$", value.strip()))


def is_valid_cipher_suite(value: str) -> bool:
    token = value.strip()
    if not is_cipher_name(token):
        return False
    # Classic suites use _WITH_; TLS 1.3 style suites start with TLS_AES_/TLS_CHACHA20_/TLS_SM4_.
    if "_WITH_" in token:
        return True
    return token.startswith("TLS_AES_") or token.startswith("TLS_CHACHA20_") or token.startswith("TLS_SM4_")


def merge_cipher_grades(
    destination: Dict[str, Dict[str, str]],
    incoming: Dict[str, Dict[str, str]],
) -> None:
    for version, grade_map in incoming.items():
        target = destination.setdefault(version, {})
        for suite, grade in grade_map.items():
            target[suite] = grade


def normalize_tls_version(raw: str) -> str:
    raw = raw.strip()
    if raw == "TLSv1":
        return "TLSv1.0"
    if raw == "TLSv1.1":
        return "TLSv1.1"
    if raw == "TLSv1.2":
        return "TLSv1.2"
    if raw == "TLSv1.3":
        return "TLSv1.3"
    return raw


def tls_sort_key(version: str) -> int:
    normalized = normalize_tls_version(version)
    try:
        return TLS_VERSION_ORDER.index(normalized)
    except ValueError:
        return len(TLS_VERSION_ORDER)

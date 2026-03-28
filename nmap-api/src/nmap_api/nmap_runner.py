from __future__ import annotations

import re
import shlex
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


@dataclass
class NmapScanData:
    command: str
    resolved_ip: str | None
    open_ports: List[Dict[str, str]]
    tls_versions: List[str]
    tls_ciphers: Dict[str, List[str]]
    script_outputs: Dict[str, str]


def build_nmap_command(domain: str, full_port_scan: bool, include_udp: bool) -> List[str]:
    base = ["nmap", "-Pn", "-sV", "--script", ",".join(SCRIPT_SET), "-oX", "-"]

    if include_udp:
        if full_port_scan:
            # Full mode: all TCP + all UDP ports.
            base += ["-sS", "-sU", "-p", "T:1-65535,U:1-65535"]
        else:
            # Normal mode: top TCP + top UDP ports.
            base += ["-sS", "-sU", "--top-ports", "1000"]
    else:
        if full_port_scan:
            # Full mode TCP-only.
            base += ["-sS", "-p-"]
        else:
            # Normal mode TCP-only.
            base += ["-sS", "--top-ports", "1000"]

    base += [domain]
    return base


def run_nmap(domain: str, full_port_scan: bool, include_udp: bool) -> NmapScanData:
    cmd = build_nmap_command(domain, full_port_scan, include_udp)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"nmap failed: {proc.stderr.strip() or proc.stdout.strip()}")

    return parse_nmap_xml(cmd, proc.stdout)


def parse_nmap_xml(cmd: List[str], xml_output: str) -> NmapScanData:
    root = ET.fromstring(xml_output)

    resolved_ip = None
    open_ports: List[Dict[str, str]] = []
    tls_versions: set[str] = set()
    tls_ciphers: Dict[str, set[str]] = {}
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
                    script_output = script.attrib.get("output", "")
                    if script_id:
                        existing = script_outputs.get(script_id, "")
                        joined = (existing + "\n" + script_output).strip() if existing else script_output
                        script_outputs[script_id] = joined

                    if script_id == "ssl-enum-ciphers":
                        versions, ciphers = parse_ssl_enum_script(script)
                        tls_versions.update(versions)
                        for version, suites in ciphers.items():
                            tls_ciphers.setdefault(version, set()).update(suites)

    ordered_versions = sorted(tls_versions, key=tls_sort_key)
    ordered_ciphers = {k: sorted(v) for k, v in tls_ciphers.items()}

    return NmapScanData(
        command=shlex.join(cmd),
        resolved_ip=resolved_ip,
        open_ports=open_ports,
        tls_versions=ordered_versions,
        tls_ciphers=ordered_ciphers,
        script_outputs=script_outputs,
    )


def parse_ssl_enum_script(script_elem: ET.Element) -> Tuple[List[str], Dict[str, List[str]]]:
    versions: set[str] = set()
    ciphers: Dict[str, set[str]] = {}

    output_text = script_elem.attrib.get("output", "")
    current_version = None
    for line in output_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.endswith(":") and ("TLS" in stripped or "SSL" in stripped):
            current_version = stripped[:-1]
            versions.add(current_version)
            ciphers.setdefault(current_version, set())
            continue

        if current_version and re.match(r"^[A-Z0-9_\-]+$", stripped):
            ciphers[current_version].add(stripped)

    for table in script_elem.findall("table"):
        table_key = table.attrib.get("key", "")
        if "TLS" in table_key or "SSL" in table_key:
            version = normalize_tls_version(table_key)
            versions.add(version)
            ciphers.setdefault(version, set())

            for subtable in table.findall("table"):
                cipher = extract_cipher_name(subtable)
                if cipher:
                    ciphers[version].add(cipher)

    out = {version: sorted(suites) for version, suites in ciphers.items()}
    return sorted(versions, key=tls_sort_key), out


def extract_cipher_name(table_elem: ET.Element) -> str | None:
    for elem in table_elem.findall("elem"):
        key = elem.attrib.get("key", "")
        if key == "name" and elem.text:
            return elem.text.strip()
    return None


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

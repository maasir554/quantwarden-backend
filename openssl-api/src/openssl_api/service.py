from __future__ import annotations

import ipaddress
import re
import socket
from datetime import datetime, UTC

from .openssl_runner import (
    CommandResult,
    openssl_ciphers,
    openssl_s_client,
    openssl_tls13_groups,
    openssl_x509_from_pem,
)
from .parsers import decompose_cipher_suite, parse_certificate_text, parse_s_client_brief
from .schemas import OpenSSLProfileRequest, OpenSSLProfileResponse, RawDebug, VersionProbe


TLS_PROBES: list[tuple[str, str]] = [
    ("TLSv1.0", "-tls1"),
    ("TLSv1.1", "-tls1_1"),
    ("TLSv1.2", "-tls1_2"),
    ("TLSv1.3", "-tls1_3"),
]


def run_openssl_profile(req: OpenSSLProfileRequest) -> OpenSSLProfileResponse:
    raw_cmds: list[str] = []
    raw_outputs: dict[str, str] = {}

    def _capture(result: CommandResult) -> None:
        raw_cmds.append(result.command)
        if req.include_raw_debug:
            raw_outputs[result.command] = _clip(result.output)

    ciphers_result = openssl_ciphers(req.timeout_seconds)
    _capture(ciphers_result)
    candidates_by_version = _parse_cipher_candidates(ciphers_result.output)
    groups_result = openssl_tls13_groups(req.timeout_seconds)
    _capture(groups_result)
    queried_groups = parse_tls_groups(groups_result.output)

    version_probes: list[VersionProbe] = []
    all_accepted_ciphers: list[str] = []

    sni = req.target.strip("[]")
    resolved_ip = _resolve_target_ip(req.target)
    forced_probe_timeout = max(3, min(5, req.timeout_seconds))
    group_probe_timeout = max(2, min(3, req.timeout_seconds))

    for version_label, tls_flag in TLS_PROBES:
        probe = openssl_s_client(
            target=req.target,
            port=req.port,
            sni=sni,
            timeout_seconds=req.timeout_seconds,
            tls_flag=tls_flag,
        )
        _capture(probe)

        handshake = parse_s_client_brief(probe.output)
        is_supported = probe.return_code == 0 and bool(handshake.cipher)

        accepted: list[str] = []
        for candidate in candidates_by_version.get(version_label, [])[:24]:
            forced = openssl_s_client(
                target=req.target,
                port=req.port,
                sni=sni,
                timeout_seconds=forced_probe_timeout,
                tls_flag=tls_flag,
                cipher=candidate if version_label != "TLSv1.3" else None,
                ciphersuite=candidate if version_label == "TLSv1.3" else None,
            )
            _capture(forced)

            forced_hs = parse_s_client_brief(forced.output)
            if forced.return_code == 0 and forced_hs.cipher and forced_hs.cipher.upper() == candidate.upper():
                accepted.append(candidate)

        all_accepted_ciphers.extend(accepted)
        version_probes.append(
            VersionProbe(
                tls_version=version_label,
                supported=is_supported,
                negotiated_cipher=handshake.cipher,
                negotiated_protocol=handshake.protocol,
                negotiated_group=handshake.negotiated_group,
                accepted_ciphers_in_client_offer_order=accepted,
                cipher_breakdowns=[decompose_cipher_suite(s) for s in accepted],
            )
        )

    cert_probe = openssl_s_client(
        target=req.target,
        port=req.port,
        sni=sni,
        timeout_seconds=req.timeout_seconds,
        tls_flag="-tls1_2",
        showcerts=True,
    )
    _capture(cert_probe)

    first_pem = _extract_first_pem(cert_probe.output)
    cert_summary_text = ""
    if first_pem:
        cert_text_result = openssl_x509_from_pem(first_pem, req.timeout_seconds)
        _capture(cert_text_result)
        cert_summary_text = cert_text_result.output

    cert_summary = parse_certificate_text(cert_summary_text)

    supported_groups = _probe_tls13_groups(
        target=req.target,
        port=req.port,
        sni=sni,
        groups=queried_groups,
        timeout_seconds=group_probe_timeout,
        capture=_capture,
    )

    tls_kex = sorted(
        {
            value
            for p in version_probes
            for value in [p.negotiated_group, *[b.key_exchange for b in p.cipher_breakdowns]]
            if value
        }
        | set(supported_groups)
    )
    tls_enc = sorted(
        {
            b.encryption
            for p in version_probes
            for b in p.cipher_breakdowns
            if b.encryption
        }
    )
    tls_sig = sorted(
        {
            b.authentication
            for p in version_probes
            for b in p.cipher_breakdowns
            if b.authentication
        }
    )

    response = OpenSSLProfileResponse(
        target=req.target,
        port=req.port,
        resolved_ip=resolved_ip,
        scanned_at=datetime.now(UTC),
        tls_versions=version_probes,
        tls_negotiation_order=all_accepted_ciphers,
        tls_key_exchange_algorithms=tls_kex,
        tls_encryption_algorithms=tls_enc,
        tls_signature_algorithms=tls_sig,
        queried_groups=queried_groups,
        supported_groups=supported_groups,
        certificate=cert_summary,
        raw_debug=RawDebug(commands=raw_cmds, command_outputs=raw_outputs) if req.include_raw_debug else None,
        metadata={
            "mode": "deep",
            "openssl_probe": "s_client",
        },
    )
    return response


def _parse_cipher_candidates(ciphers_output: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {k: [] for k, _ in TLS_PROBES}
    for line in ciphers_output.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        suite = parts[0].strip()
        proto = parts[1].strip().upper()

        if proto in {"TLSV1.3", "TLSV1_3"}:
            if suite.startswith("TLS_"):
                out["TLSv1.3"].append(suite)
        elif proto in {"TLSV1.2", "TLSV1.1", "TLSV1", "SSLV3"}:
            out["TLSv1.2"].append(suite)
            out["TLSv1.1"].append(suite)
            out["TLSv1.0"].append(suite)

    for key in out:
        out[key] = _dedupe_keep_order(out[key])
    return out


def _dedupe_keep_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        key = v.upper()
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return out


def _extract_first_pem(s_client_output: str) -> str | None:
    match = re.search(
        r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----",
        s_client_output,
    )
    if match:
        return match.group(0)
    return None


def _clip(text: str, limit: int = 6000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[truncated]..."


def parse_tls_groups(raw: str) -> list[str]:
    text = raw.strip()
    if not text:
        return []

    # openssl list -tls-groups -tls1_3 returns a colon-separated line
    line = text.splitlines()[-1].strip()
    groups = [part.strip() for part in line.split(":") if part.strip()]
    return _dedupe_keep_order(groups)


def _probe_tls13_groups(
    *,
    target: str,
    port: int,
    sni: str,
    groups: list[str],
    timeout_seconds: int,
    capture,
) -> list[str]:
    out: list[str] = []
    for group in groups:
        result = openssl_s_client(
            target=target,
            port=port,
            sni=sni,
            timeout_seconds=timeout_seconds,
            tls_flag="-tls1_3",
            groups=group,
        )
        capture(result)

        parsed = parse_s_client_brief(result.output)
        supported = result.return_code == 0 and bool(parsed.cipher)
        if supported:
            negotiated = (parsed.negotiated_group or "").strip()
            out.append(negotiated or group)
    return _dedupe_keep_order(out)


def _resolve_target_ip(target: str) -> str | None:
    raw = target.strip().strip("[]")
    if not raw:
        return None

    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(raw, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except OSError:
        return None

    for info in infos:
        sockaddr = info[4]
        if sockaddr:
            ip = sockaddr[0]
            if ip:
                return ip
    return None

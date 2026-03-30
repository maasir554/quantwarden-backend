# Nmap Security Intelligence API

A Python FastAPI project that uses Nmap to extract critical security intelligence and post-quantum cryptography safety insights from a target domain.

## What It Collects

- Open ports and service details (service, product, version, extra info)
- TCP scanning by default (UDP optional via request flag)
- All detected supported TLS/SSL versions from `ssl-enum-ciphers`
- All detected cipher suites grouped by TLS version
- Nmap script-driven vulnerability indicators:
  - Heartbleed
  - POODLE
  - CCS Injection
  - SSLv2 support
  - Weak DH params indicators
- Security grading (A-F + numeric score)
- Compliance checks (practical heuristic checks for PCI DSS and HIPAA)
- Certificate-chain issue indicators (self-signed, missing intermediate, hostname mismatch, expiry hints)
- Security headers analysis
- Post-quantum safety intelligence summary

## Important Notes

- "All supported TLS versions/ciphers" is based on what Nmap scripts can enumerate for discovered ports and script coverage.
- Compliance and grading are automated heuristics intended for triage, not an official audit substitute.
- Post-quantum analysis focuses on practical migration intelligence (risk posture and recommendations).

## Project Structure

```text
nmap-api/
  main.py
  requirements.txt
  README.md
  scripts/
    setup.sh
    run.sh
  src/
    nmap_api/
      __init__.py
      schemas.py
      nmap_runner.py
      analysis.py
      service.py
```

## Prerequisites

1. Python 3.13 or 3.12 (recommended: 3.13)
2. Nmap installed and available in PATH

macOS:

```bash
brew install nmap
```

## Setup

From monorepo root:

```bash
cd nmap-api
bash scripts/setup.sh
```

If your default `python3` is 3.14, run setup with an explicit interpreter:

```bash
cd nmap-api
PYTHON_BIN=python3.13 bash scripts/setup.sh
```

Or manually:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
```

## Run

```bash
cd nmap-api
source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8010 --reload
```

Quick run script:

```bash
cd nmap-api
bash scripts/run.sh
```

Health endpoint:

```bash
curl http://localhost:8010/
```

## API Usage

### POST `/api/v1/security-intelligence`

Request body:

```json
{
  "domain": "example.com",
  "full_port_scan": false,
  "udp_scan": false,
  "response_profile": "full"
}
```

- `udp_scan=false` (default): TCP-only scan
- `udp_scan=true`: include UDP scan
- `full_port_scan=false`: top ports for selected protocols (faster)
- `full_port_scan=true`: all ports for selected protocols (slowest, broadest)
- `response_profile="full"`: complete evidence-rich response
- `response_profile="concise"`: trimmed evidence/lists for dashboard/API clients

### Async scan jobs (recommended for long scans)

Create job:

```bash
curl -X POST http://localhost:8010/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "full_port_scan": true, "udp_scan": true, "response_profile": "concise"}'
```

Example response:

```json
{
  "scan_id": "d2d9eb7d-7f96-4cdf-9dc0-f5e50f4a78f2",
  "status": "queued"
}
```

Poll status/result:

```bash
curl "http://localhost:8010/api/v1/scans/d2d9eb7d-7f96-4cdf-9dc0-f5e50f4a78f2"
```

Optional lightweight poll (omit heavy result payload):

```bash
curl "http://localhost:8010/api/v1/scans/d2d9eb7d-7f96-4cdf-9dc0-f5e50f4a78f2?include_result=false"
```

Job states:

- `queued`
- `running`
- `completed` (result included if `include_result=true`)
- `failed` (error message populated)

Example:

```bash
curl -X POST http://localhost:8010/api/v1/security-intelligence \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "full_port_scan": false, "udp_scan": false, "response_profile": "concise"}'
```

### POST `/ethical-scan` (or `/api/v1/ethical-scan`)

Stateless, polite PQC-oriented scan focused on HTTPS/TLS and SSH signals.

Request body:

```json
{
  "target": "example.com",
  "include_tls_version_tests": true,
  "user_agent": "PQCSecurityScanner/1.0 (+https://example.com/scanner-info; security@example.com)"
}
```

Example:

```bash
curl -X POST http://localhost:8010/ethical-scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "include_tls_version_tests": true}'
```

Highlights:

- Scans only ports 443 and 22 with conservative timing flags.
- Uses SSL/TLS and SSH NSE scripts for PQC readiness evidence.
- Adds `ssh_found` to indicate whether SSH was positively detected.
- Returns in-memory structured results only (no scan files written to disk).

## Response Highlights

- `open_ports`: detailed discovered services
- `supported_tls_versions`: list of TLS/SSL versions discovered
- `supported_cipher_suites`: map of TLS version to suites
- `vulnerabilities`: per-vulnerability findings with evidence
- `certificate_chain_issues`: issue flags and evidence
- `certificate_chain_intelligence`: chain depth/confidence, OCSP/CA issuer URLs, SCT signal
- `security_headers`: present/missing headers and score
- `compliance`: PCI DSS and HIPAA pass/fail with notes
- `pqc_safety_intelligence`: key algorithm risk, PFS signal, recommendations
- `security_grade`: numeric score + letter grade + reasons
- `findings`: normalized finding objects with severity, confidence, evidence, and remediation
- `recommendations`: prioritized action plan (`p0`-`p3`)
- `pqc_scorecard`: dedicated PQC score, dimension scores, and top risks
- `intelligence_summary`: concise risk summary and top actions
- `raw_nmap_command`: exact command executed

## Troubleshooting

- Error: `nmap is not installed or not in PATH`
  - Install nmap and retry.
- Error mentions root privileges
  - The API now auto-uses non-root TCP connect scanning when root-only scan types are unavailable.
  - If `udp_scan=true`, run the API with elevated privileges to enable UDP probing.
- DNS resolution failures
  - Verify domain spelling and network DNS access.
- Long scans
  - Use `full_port_scan=false` first, then run deep scans only when needed.
  - Enabling `udp_scan=true` can be significantly slower/noisier depending on network filtering.

## Security Considerations

- Scan only targets you own or are explicitly authorized to test.
- Running intrusive scans against unauthorized systems may violate law/policy.

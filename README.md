# QuantWarden Monorepo

This repository now contains multiple APIs that can be run together.

## Services

- OneForAll subdomain API
- Subfinder API
- PySSL API
- Nmap Security Intelligence API

## Default ports

- OneForAll API: 8002
- Subfinder API: 8085
- PySSL API: 8000
- Nmap API: 8010

## Quick start with one command

Run from monorepo root:

```bash
python3 start_monorepo_servers.py
```

What this does:

- Starts OneForAll API
- Starts Subfinder API
- Starts PySSL API
- Starts Nmap API
- Detects busy ports and automatically reassigns to free ports
- Injects runtime env vars for Subfinder so it can reach OneForAll

Press Ctrl+C to stop all services.

## Interactive setup mode

Use setup mode to choose ports interactively and optionally persist env values:

```bash
python3 start_monorepo_servers.py --setup
```

Setup mode asks:

- OneForAll port
- Subfinder port
- PySSL port
- Nmap port
- Whether to persist Subfinder env settings into subfinder-api/.env

## Persist env updates into subfinder-api/.env

If you want the script to save the resolved URL and listen address:

```bash
python3 start_monorepo_servers.py --persist-env
```

Keys written or updated in subfinder-api/.env:

- ONEFORALL_API_URL
- SUBFINDER_API_ADDR

If you do not use this flag, env values are applied only at runtime for that launch.

## Manual startup commands

If you prefer to run each service yourself:

### 1) Start OneForAll API

```bash
cd one-for-all-subdomains
python3 run_api.py --port 8002
```

### 2) Start Subfinder API with OneForAll integration

```bash
cd subfinder-api
ONEFORALL_API_URL=http://127.0.0.1:8002 SUBFINDER_API_ADDR=:8085 go run .
```

### 3) Start PySSL API on a non-conflicting port

```bash
cd pyssl-api
python3 -m uvicorn main:app --host 0.0.0.0 --port 8001
```

### 4) Start Nmap API on a non-conflicting port

```bash
cd nmap-api
python3 -m uvicorn main:app --host 0.0.0.0 --port 8010 --reload
```

## Optional explicit port arguments

You can pass explicit preferred ports to launcher:

```bash
python3 start_monorepo_servers.py --oneforall-port 8002 --subfinder-port 8085 --pyssl-port 8000
```

Include Nmap explicitly if desired:

```bash
python3 start_monorepo_servers.py --oneforall-port 8002 --subfinder-port 8085 --pyssl-port 8000 --nmap-port 8010
```

If a preferred port is busy, the launcher logs a warning and picks the next available port.

## Logs and colors

The launcher prints colorized logs:

- Green: info
- Yellow: warnings
- Red: errors
- Colored prefixes for each service stream

Disable colors by setting NO_COLOR=1.

## Python virtual environments

Yes, the launcher now handles service-specific Python virtualenvs.

Resolution order per Python service:

1. Explicit CLI override (if provided)
2. Service local `.venv/bin/python`
3. Service local `venv/bin/python`
4. Fallback to `--python-cmd` (default `python3`)

Override examples:

```bash
python3 start_monorepo_servers.py \
	--oneforall-python /abs/path/to/oneforall/.venv/bin/python \
	--pyssl-python /abs/path/to/pyssl/venv/bin/python \
	--nmap-python /abs/path/to/nmap-api/.venv/bin/python
```

This keeps dependencies isolated between `one-for-all-subdomains`, `pyssl-api`, and `nmap-api` while still allowing a fallback when no venv exists.

## MCP Server For AI Agents

The monorepo now includes an MCP server so external AI agents can call backend APIs through a single tool interface.

Location:

- `mcp-monorepo-server/`

Quick start:

```bash
cd mcp-monorepo-server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python server.py
```

Client config templates:

- Claude Desktop / Cursor templates: `mcp-monorepo-server/config-examples/`
- VS Code workspace MCP config: `.vscode/mcp.json`

Common tools exposed by this MCP server:

- `nmap_security_intelligence`
- `nmap_ethical_scan`
- `pyssl_analysis`
- `subfinder_combined`
- `subfinder_only`
- `assetfinder_only`
- `monorepo_api_request` (generic request wrapper)

By default the server targets localhost service ports from this monorepo launcher. Override with env vars if needed:

- `ONEFORALL_API_URL`
- `SUBFINDER_API_URL`
- `PYSSL_API_URL`
- `NMAP_API_URL`


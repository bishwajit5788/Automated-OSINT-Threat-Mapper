# ⚡ AetherMap-OSINT — Automated OSINT Threat Mapper

<p align="center">
  <a href="https://automated-osint-threat-mapper.vercel.app" target="_blank"><img src="https://img.shields.io/badge/Live_Demo-Vercel-000000?style=for-the-badge&logo=vercel&logoColor=white" alt="Live Demo" /></a>
  <img src="https://img.shields.io/badge/FastAPI-Python-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/React-Vite-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/CI-GitHub_Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white" alt="CI" />
</p>

AetherMap-OSINT maps public-facing assets from passive OSINT and performs bounded TCP service discovery, lightweight banner fingerprinting, NVD CPE/CVE correlation, risk scoring, and scan-to-scan change detection.

> **Authorization:** active TCP scanning sends connection probes to the selected target. Use it only against systems you are explicitly authorized to assess. No exploitation or credential attacks are performed.

## Current pipeline

```text
Target FQDN
   │
   ├──► DNS resolution ───────────────► Root IP
   │
   ├──► crt.sh Certificate Transparency ► Observed subdomains
   │                                      │
   │                                      └──► DNS resolution per asset (future expansion)
   │
   └──► bounded TCP connect scan ──────► Open ports
                                           │
                                           └──► service/banner fingerprint
                                                   │
                                                   └──► product + version evidence
                                                            │
                                                            └──► NVD CPE lookup
                                                                     │
                                                                     └──► NVD CVE lookup
                                                                              │
                                                                              └──► confidence + severity
                                                                                       │
                                                                                       └──► risk score

Every completed scan ──► SQLite history ──► added/removed ports/assets
```

NVD describes CPE as a standardized way to identify classes of products/platforms and provides APIs for CPE/CVE correlation. citeturn0search0

## What is real now

- DNS resolution uses the local resolver.
- Certificate Transparency discovery queries `crt.sh`.
- The scanner performs real TCP connection probes against a bounded port profile or a caller-supplied list of up to 128 ports.
- HTTP and SSH responses are fingerprinted when available; the scanner does not pretend that a port number alone proves a product/version.
- Product/version evidence can be correlated with the NVD CPE and CVE APIs.
- CVEs are marked `correlated-cpe`; weak fingerprints are not promoted into fabricated findings.
- SQLite stores scan snapshots and exposes a history-diff endpoint.
- The demo endpoint remains isolated and explicitly synthetic.

## API

### `POST /api/recon`

```json
{
  "domain": "example.com",
  "ports": [22, 80, 443, 8080]
}
```

Omit `ports` to use the built-in common-port profile. Set `SCAN_PORTS` to override the default profile through deployment configuration.

### `GET /api/recon/history/{domain}`

Returns the difference between the two most recent stored scans:

```json
{
  "domain": "example.com",
  "added_ports": [8443],
  "removed_ports": [8080],
  "added_assets": ["api.example.com"],
  "removed_assets": []
}
```

### `GET /api/recon/sample`

Synthetic UI/demo data only. It does not scan the target and must not be interpreted as live evidence.

## Service fingerprinting limitations

This is **not Nmap** and should not be described as an Nmap replacement. The current scanner uses TCP connect behavior and small protocol probes. It does not yet perform SYN scanning, UDP scanning, OS detection, NSE scripts, full TLS fingerprinting, or exhaustive protocol negotiation.

Likewise, a CPE/CVE match is not automatically proof that a host is vulnerable. NVD applicability statements can include version ranges, configuration conditions, and logical expressions. The application should treat the current correlation as triage evidence and require verification before remediation or incident conclusions. citeturn0search0

## Architecture

```text
React + React Flow
       │
       ▼
FastAPI API
       │
       ├── Domain validation
       ├── DNS resolver
       ├── crt.sh collector
       ├── TCP scanner
       ├── Banner fingerprinting
       ├── NVD CPE/CVE correlator
       ├── Heuristic risk scoring
       └── SQLite history/diff
```

## Local development

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

API: `http://localhost:8000`  
Swagger: `http://localhost:8000/docs`

### Frontend

```bash
cd frontend
npm ci
npm run dev
```

Set `VITE_API_URL` to the backend origin when frontend and API are deployed separately. Configure backend `ALLOWED_ORIGINS` to the exact frontend origin.

## Repository structure

```text
Automated-OSINT-Threat-Mapper/
├── .github/workflows/ci.yml
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── demo_data.py
│   │   ├── engines.py
│   │   ├── main.py
│   │   └── schemas.py
│   ├── tests/test_schemas.py
│   ├── tests/test_scanner.py
│   └── requirements.txt
├── frontend/
│   └── src/
└── README.md
```

## Roadmap

1. Expand fingerprinting with protocol-specific, non-invasive probes and TLS certificate metadata.
2. Add DNS resolution and scan correlation for discovered subdomains, with strict concurrency/rate limits.
3. Improve CPE selection using vendor/product evidence instead of a small static mapping.
4. Add NVD API-key support, caching, retry/backoff, and local vulnerability indexing.
5. Add evidence records with source, timestamp, collection method, and confidence for every finding.
6. Add historical UI with port/asset/version/CVE changes between scans.
7. Add authentication, rate limiting, audit logging, job queues, and deployment egress controls.
8. Add optional external provider adapters such as Shodan only when credentials and authorization are explicitly configured.

## Responsible use

Use this project only within an approved assessment scope. A discovered open port is an observation, not a vulnerability. A CPE/CVE match is a correlation, not proof of exploitability. Do not add exploit or credential-attack functionality to the scanner without a separate, explicit authorized lab workflow.

## License

MIT

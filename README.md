# ⚡ AetherMap-OSINT — Automated OSINT Threat Mapper

<p align="center">
  <img src="https://img.shields.io/badge/FastAPI-Python-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/React-Vite-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/Scanner-v3.0-111827?style=for-the-badge" alt="Scanner v3" />
  <img src="https://img.shields.io/badge/CI-GitHub_Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white" alt="CI" />
</p>

AetherMap-OSINT maps public-facing assets from passive OSINT, safely resolves discovered hosts, performs bounded real TCP connect scanning, gathers lightweight protocol/TLS evidence, correlates observed product versions with NVD CPE/CVE data, scores risk, and stores stable historical snapshots.

> **Authorization:** active TCP/TLS probes contact selected target infrastructure. Use only against systems you are explicitly authorized to assess. No exploitation, credential attacks, brute force, or destructive testing is performed.

## Scanner v3 pipeline

```text
Target FQDN
   │
   ├──► DNS ───────────────► public IPs only
   │
   ├──► crt.sh CT ─────────► bounded asset inventory
   │                           │
   │                           └──► DNS per discovered hostname
   │                                      │
   │                                      └──► private/loopback/metadata IP rejection
   │
   └──────────────────────────────────────────────┐
                                                  ▼
                                      bounded TCP connect scan
                                                  │
                                      ┌───────────┴───────────┐
                                      ▼                       ▼
                               protocol/banner          TLS handshake
                                      │                       │
                                      └───────────┬───────────┘
                                                  ▼
                                      product/version evidence
                                                  │
                                                  ▼
                                          NVD CPE resolution
                                                  │
                                                  ▼
                                           NVD CVE correlation
                                                  │
                                      confidence + CVSS severity
                                                  │
                                                  ▼
                                         risk/threat score
                                                  │
                         ┌────────────────────────┴────────────────────┐
                         ▼                                             ▼
                 stable SQLite history                         JSON API response
                         │
                         └──► added/removed assets, ports, service/CVE changes
```

NVD defines CPE as a standardized identification method for products/platforms and provides CPE/CVE APIs for vulnerability applicability data. A CPE/CVE correlation remains triage evidence; it is not by itself proof that a deployed instance is exploitable. citeturn0search0

## What v3 solves

- **Root-only scanning:** crt.sh-discovered hostnames are now resolved and scanned within a configurable bounded asset limit.
- **SSRF/network-pivot risk:** only globally routable public IPs are accepted; loopback, private, link-local, multicast, reserved, unspecified and cloud-metadata addresses are rejected.
- **Shallow evidence:** TCP connect evidence, protocol banners, and TLS version/ALPN/certificate hash are retained when available.
- **Fabricated CPEs:** unresolved product/version combinations remain unresolved instead of receiving an invented CPE.
- **Weak CVE claims:** every correlated CVE carries confidence and evidence describing the observed version/CPE relationship.
- **History always changing:** volatile timestamps/execution duration are excluded from the stable snapshot fingerprint.
- **NVD fragility:** API-key support, retries, rate-limit handling, timeouts and serialized requests reduce upstream failure pressure.
- **Unbounded fan-out:** asset and port counts are bounded at both request and deployment levels.
- **History API validation:** history queries use the same FQDN validation as scans.

## API

### `POST /api/recon`

```json
{
  "domain": "example.com",
  "ports": [22, 80, 443, 8080],
  "max_assets": 25
}
```

`ports` is optional and limited to 128 TCP ports. `max_assets` is bounded by the deployment setting and request schema. If `ports` is omitted, the built-in common-service profile is used.

### `GET /api/recon/history/{domain}`

Returns stable changes between the two latest scans:

```json
{
  "domain": "example.com",
  "added_ports": [8443],
  "removed_ports": [8080],
  "added_assets": ["api.example.com"],
  "removed_assets": [],
  "changed_services": [{"host": "api.example.com", "port": 443, "protocol": "tcp"}]
}
```

### `GET /api/recon/sample`

Synthetic demo data only. It is not live evidence and performs no network scan.

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| `ALLOWED_ORIGINS` | Exact frontend CORS origins | localhost development origins |
| `SCAN_PORTS` | Comma-separated default TCP profile | built-in common ports |
| `SCAN_CONCURRENCY` | Maximum concurrent TCP probes | `32` |
| `MAX_ASSETS` | Deployment-wide asset ceiling | `25` |
| `SCAN_CONNECT_TIMEOUT` | TCP connection timeout | `1.5` seconds |
| `NVD_TIMEOUT` | NVD HTTP timeout | `10` seconds |
| `NVD_API_KEY` | Optional NVD API key | unset |
| `AETHERMAP_HISTORY_DB` | SQLite database path | `data/aethermap_history.sqlite3` |

## Evidence and confidence

A finding is built from observable evidence rather than a port-number guess:

```text
TCP connect
   + banner/protocol evidence
   + TLS evidence (when applicable)
          ↓
product/version
          ↓
exact CPE candidate (when resolvable)
          ↓
NVD CVEs
          ↓
confidence score
```

The scanner deliberately reports **correlation**, not exploitability. Vendor backports, configuration, package patches, feature flags, mitigations and NVD applicability conditions can affect whether a deployed service is actually vulnerable.

## Scope and safety controls

- TCP connect scanning only; no SYN/raw-packet implementation.
- No UDP scanning, OS fingerprinting, NSE-style scripting, credential testing, brute force, exploitation, persistence, or destructive checks.
- Asset fan-out is bounded.
- TCP concurrency is bounded.
- Only public globally routable addresses are scanned.
- The root hostname and each discovered hostname are independently resolved before scanning.
- No arbitrary HTTP redirects are followed by the scanner's target probes.
- The NVD client uses bounded retries and serialized requests.

## Current limitations

This is now a serious **safe vulnerability-triage scanner**, but it is still not a replacement for Nmap, Nuclei, Greenbone/OpenVAS, commercial ASM, or a full authenticated vulnerability-management platform.

Remaining gaps include:

1. CPE applicability evaluation is still narrower than NVD's complete logical configuration/version-range model.
2. Service fingerprints cover common HTTP/SSH/TLS evidence rather than every protocol.
3. TLS evidence currently records handshake metadata and certificate hash, not a complete cipher/compliance audit.
4. The default port profile is bounded; full-range scanning requires an explicit future job/profile design rather than silently scanning 65,535 ports.
5. IPv6 scanning and dual-stack correlation need further hardening.
6. NVD results are live-correlated; a production deployment should add a local vulnerability cache/index.
7. No authenticated application/API scanning is performed.
8. No cloud-provider inventory, WHOIS/RDAP, ASN/BGP or external threat-intelligence provider is enabled by default.
9. Authentication/RBAC, persistent job queues, audit logging and distributed workers are not yet implemented.
10. The frontend still needs a dedicated scan-profile/history/evidence UX to expose the complete v3 backend model.

## Production roadmap

### Phase 1 — scanner correctness
- richer protocol probes with strict per-protocol time budgets
- complete TLS metadata and certificate-chain analysis
- stronger CPE selection and NVD applicability evaluation
- local NVD cache/index with freshness metadata
- IPv4/IPv6 asset correlation

### Phase 2 — ASM intelligence
- RDAP/WHOIS
- ASN/BGP ownership mapping
- passive DNS
- certificate relationship graph
- optional Shodan/Censys-style adapters behind explicit credentials and scope controls
- cloud asset adapters

### Phase 3 — platform hardening
- authentication and RBAC
- background scan jobs and worker queue
- rate limiting and per-tenant quotas
- audit logs
- signed/exportable evidence bundles
- PostgreSQL/object storage for multi-user deployments
- metrics, tracing and structured security logs

### Phase 4 — vulnerability verification
Add only non-destructive, explicitly scoped verification modules. Verification should produce separate evidence from passive correlation and never silently convert a CVE match into an exploitation claim.

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

### Frontend

```bash
cd frontend
npm ci
npm run dev
```

Set `VITE_API_URL` when the API is deployed separately. Set `ALLOWED_ORIGINS` to the exact frontend origin in production.

## Repository structure

```text
Automated-OSINT-Threat-Mapper/
├── .github/workflows/ci.yml
├── backend/
│   ├── app/
│   │   ├── demo_data.py
│   │   ├── engines.py
│   │   ├── main.py
│   │   └── schemas.py
│   ├── tests/
│   │   ├── test_schemas.py
│   │   └── test_scanner.py
│   └── requirements.txt
├── frontend/
│   └── src/
└── README.md
```

## Responsible use

Use this project only within an approved assessment scope. An open port is an observation, not a vulnerability. A CPE/CVE match is a correlation, not proof of exploitability. Keep active scanning disabled for assets outside an explicitly authorized scope.

## License

MIT

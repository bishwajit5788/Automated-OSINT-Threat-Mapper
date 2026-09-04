# ⚡ AetherMap-OSINT — Automated OSINT Threat Mapper

<p align="center">
  <img src="https://img.shields.io/badge/FastAPI-Python-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/React-Vite-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/Scanner-v3.2-111827?style=for-the-badge" alt="Scanner v3.2" />
  <img src="https://img.shields.io/badge/CI-GitHub_Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white" alt="CI" />
</p>

AetherMap-OSINT is a bounded, non-destructive attack-surface and vulnerability-triage platform. It combines Certificate Transparency discovery, public DNS resolution, real TCP/UDP probing, protocol/TLS evidence collection, NVD CPE/CVE correlation, confidence scoring, and stable historical change detection.

> **Authorization:** active network probes contact selected target infrastructure. Use only against systems you are explicitly authorized to assess. No exploitation, credential attacks, brute force, persistence, or destructive testing is performed.

## v3.2 TLS assessment and production hardening

- **Asset fan-out:** crt.sh hostnames are individually resolved and scanned within request/deployment ceilings.
- **Network safety:** only globally routable addresses are eligible for active scanning; private, loopback, link-local, multicast, reserved and unspecified addresses are rejected.
- **Real TCP/UDP scanning:** bounded TCP connects plus protocol-aware UDP probes with configurable limits.
- **Evidence-first detection:** connection, protocol/banner, TLS and certificate evidence are retained instead of fabricating findings.
- **TLS certificate intelligence:** subject, SAN, issuer, validity period, expiry countdown, fingerprint, key type/size/curve and signature algorithm are collected when the certificate is parseable.
- **TLS trust checks:** hostname validation and system trust-store chain validation are performed separately from the evidence-preserving handshake.
- **TLS protocol probing:** TLS 1.0, 1.1, 1.2 and 1.3 are tested independently where the local runtime permits the probe.
- **TLS cipher assessment:** bounded TLS 1.2 cipher probing plus the standard TLS 1.3 suite set when the local OpenSSL CLI is available; weak accepted suites are flagged.
- **Security-grade TLS score:** every assessed TLS service receives a 0–100 score, letter grade, finding IDs and evidence-backed remediation actions.
- **CVE triage:** NVD CPE/CVE correlation is explicit and confidence-scored; unresolved products are not assigned fabricated CPEs.
- **Stable history:** timestamps and execution duration do not cause false historical changes.
- **Operational limits:** ports, assets, concurrency and network timeouts are bounded to prevent accidental scan amplification.
- **API hardening:** request validation and history-domain validation share the same FQDN rules.

## Pipeline

```text
Target FQDN
  ├─► DNS ─► public IPv4/IPv6 candidates
  ├─► crt.sh ─► bounded hostname inventory
  │                 └─► DNS each hostname
  └──────────────────────────────► bounded TCP/UDP assessment
                                      ├─► protocol/banner evidence
                                      ├─► TLS protocol probes
                                      ├─► TLS cipher probes
                                      └─► certificate/trust analysis
                                                │
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
                                                ▼
                                  stable historical snapshots/diff
```

NVD defines CPE as a standardized product/platform identification method and provides CPE/CVE applicability data. A CPE/CVE match is triage evidence, not automatic proof that a deployed instance is exploitable. citeturn0search0

## TLS assessment output

For TLS-enabled services, the API now exposes structured fields alongside raw evidence:

```text
TLS score / grade
Supported protocols
Rejected protocols
Inconclusive protocol probes
Supported cipher suites
Weak cipher suites
Cipher enumeration completeness
Certificate subject / issuer / SAN
Certificate validity start / expiry
Days remaining
Certificate SHA-256
RSA/EC key information
Signature algorithm
TLS findings
Evidence-backed remediation actions
```

Example finding flow:

```text
TLS_CERT_EXPIRED
        ↓
severity: CRITICAL
        ↓
certificate expiry evidence
        ↓
remediation: renew and deploy a valid certificate chain
```

The TLS score is an AetherMap heuristic for triage and is not a formal compliance certification or a replacement for a dedicated TLS auditing product.

## API

### `POST /api/recon`

```json
{
  "domain": "example.com",
  "ports": [22, 80, 443, 8080],
  "max_assets": 25
}
```

`ports` is limited to 128 TCP ports. `max_assets` is bounded by the request schema and the deployment `MAX_ASSETS` ceiling.

### `GET /api/recon/history/{domain}`

Returns stable changes between the two latest scans, including asset/port additions and removals plus changed service fingerprints/CVEs.

### `GET /api/recon/sample`

Synthetic demo data only. It is not live evidence.

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| `ALLOWED_ORIGINS` | Exact frontend CORS origins | localhost origins |
| `SCAN_PORTS` | Default TCP port profile | common ports |
| `SCAN_UDP_PORTS` | UDP probe profile | `53,123,161,500,4500,5353` |
| `SCAN_CONCURRENCY` | Concurrent TCP probes | `32` |
| `MAX_ASSETS` | Deployment asset ceiling | `25` |
| `MAX_IPS_PER_HOST` | Public IPs considered per hostname | `4` |
| `SCAN_CONNECT_TIMEOUT` | TCP connect timeout | `1.5s` |
| `SCAN_UDP_TIMEOUT` | UDP response timeout | `1.5s` |
| `NVD_TIMEOUT` | NVD request timeout | `10s` |
| `NVD_API_KEY` | Optional NVD API key | unset |
| `AETHERMAP_HISTORY_DB` | SQLite history path | `data/aethermap_history.sqlite3` |

TLS assessment also uses the host's installed CA trust store and, for bounded TLS 1.3 cipher probing, an available `openssl` executable. If a capability is unavailable locally, the scanner records an inconclusive/limited result instead of pretending the test completed.

## Evidence model

```text
TCP/UDP connection
 + protocol/banner evidence
 + TLS protocol/cipher evidence
 + certificate/trust evidence
       ↓
product + version
       ↓
CPE candidate
       ↓
NVD CVEs
       ↓
confidence score
       ↓
triage finding
```

Every vulnerability finding includes source, confidence, and evidence. TLS findings likewise retain the observed evidence and a concrete remediation action. The scanner deliberately distinguishes **correlated** from **confirmed** vulnerability status because vendor backports, configuration, mitigations and applicability conditions can change real-world exposure.

## Current scope

Supported now:

- Certificate Transparency enumeration via crt.sh
- Multi-host DNS resolution
- Public-IP safety filtering
- Bounded TCP connect scanning
- Bounded UDP probes
- HTTP/SSH/limited protocol fingerprinting
- TLS 1.0/1.1/1.2/1.3 capability probing
- TLS 1.2 cipher probing and bounded TLS 1.3 cipher enumeration
- Weak cipher classification
- Certificate subject/SAN/issuer extraction
- Certificate validity and expiry assessment
- Certificate hostname and system trust-store validation
- RSA/EC certificate key information
- Certificate signature algorithm checks
- Security-grade TLS score and remediation
- NVD CPE/CVE correlation
- CVSS severity classification
- Confidence-scored evidence
- Stable SQLite scan history
- Asset/port/service/CVE change detection
- Request-level port and asset controls

Intentionally not implemented yet:

- Exploitation or credential attacks
- Raw-packet SYN scanning
- Full OS fingerprinting
- Complete protocol fingerprint coverage
- Authenticated application scanning
- Cloud inventory
- RDAP/ASN/BGP enrichment
- Distributed worker queues
- Multi-tenant RBAC
- PostgreSQL/object-storage production persistence
- Full vulnerability verification
- TLS compliance certification against every external policy/profile

These are engineering boundaries, not hidden capabilities.

## Production architecture target

```text
React/Vercel frontend
        │
        ▼
API gateway / authenticated API
        │
        ▼
background scan queue
        │
   ┌────┼────┐
   ▼    ▼    ▼
worker worker worker
   └────┼────┘
        ▼
PostgreSQL + evidence/object storage
```

**Do not deploy the scanner directly to Vercel.** Vercel is reserved for the final frontend deployment after the scanner/backend has passed local and CI validation. Network scanning workers require a runtime designed for controlled outbound network operations and long-running jobs.

## Validation

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

```bash
cd frontend
npm ci
npm run build
```

## Responsible use

Use only within an approved assessment scope. An open port is an observation, not a vulnerability. A CPE/CVE correlation is not proof of exploitability. TLS results are evidence-backed configuration observations, not proof of exploitability or formal compliance. Keep active scanning disabled for assets outside an explicitly authorized scope.

## License

MIT
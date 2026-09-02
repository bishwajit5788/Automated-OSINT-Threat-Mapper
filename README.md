# ⚡ AetherMap-OSINT (Automated OSINT Threat Mapper)

<p align="center">
  <img src="https://img.shields.io/badge/FastAPI-0.110.0-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+" />
  <img src="https://img.shields.io/badge/React-18.3.1-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/ReactFlow-12.4.2-FF0072?style=for-the-badge&logo=react&logoColor=white" alt="ReactFlow" />
  <img src="https://img.shields.io/badge/Tailwind_CSS-3.4.17-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white" alt="Tailwind CSS" />
  <img src="https://img.shields.io/badge/Vite-6.1.0-646CFF?style=for-the-badge&logo=vite&logoColor=white" alt="Vite" />
  <img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge" alt="MIT License" />
</p>

---

## 🎯 Executive Overview

**AetherMap-OSINT** is a production-grade Cyber Threat Intelligence (CTI) and External Attack Surface Management (EASM) platform. It orchestrates non-blocking, asynchronous open-source intelligence pipelines to discover an organization's digital footprint, fingerprint exposed services, correlate vulnerabilities against known CVE databases, and visualize the entire attack topology in a reactive, cyber-themed graph canvas.

```
                   ┌─────────────────────────────────────────┐
                   │       AetherMap-OSINT UI Canvas         │
                   │  (React 18 + @xyflow/react + Tailwind)  │
                   └────────────────────┬────────────────────┘
                                        │ HTTP/JSON
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │         FastAPI Async Backend           │
                   │           (Python 3.11+)                │
                   └───────┬─────────────────────────┬───────┘
                           │                         │
            ┌──────────────┴──────────────┐   ┌──────┴──────────────────────┐
            ▼                             ▼   ▼                             ▼
   ┌─────────────────┐           ┌─────────────────┐               ┌─────────────────┐
   │ Certificate     │           │ Async DNS       │               │ Shodan Port &   │
   │ Transparency    │           │ Resolver        │               │ CVE Correlator  │
   │ (crt.sh Logs)   │           │ (Non-blocking)  │               │ (Sim Engine)    │
   └─────────────────┘           └─────────────────┘               └─────────────────┘
```

---

## 🚀 Key Architectural Features

1. **Non-Blocking Asynchronous Reconnaissance Engine (`backend/app/engines.py`)**:
   - High-throughput asynchronous HTTP querying via `httpx.AsyncClient` targeting Certificate Transparency logs (`crt.sh`).
   - Non-blocking DNS resolution utilizing `asyncio.get_running_loop().getaddrinfo()` to prevent event loop starvation.
   - Concurrent task execution orchestrated via `asyncio.gather()`.
   - Comprehensive error recovery: upstream rate-limiting, network timeouts, or non-JSON payloads trigger seamless fallback pipelines without crashing the server.

2. **Network Layer Fingerprinting & CVE Correlation**:
   - Deep port mapping (22, 80, 443, 6379, 8080, 8443) simulating Shodan network intelligence.
   - Correlation with high-profile CVEs (e.g. **CVE-2021-44228 Log4Shell**, **CVE-2023-38408 OpenSSH RCE**, **CVE-2022-0543 Redis Sandbox Escape**, **CVE-2022-22965 Spring4Shell**).
   - Real-time CVSS 3.1 scoring, vulnerability impact descriptions, and remediation guidance.

3. **Reactive Topology Visualization Canvas (`frontend/src/App.jsx`)**:
   - Built on top of `@xyflow/react` with custom node renderers:
     - **Central Radar Hub**: Visualizes target root domain, composite Threat Risk Index, and live DNS status.
     - **Subdomain Leaf Nodes (Left Branch)**: Dynamic array of discovered sub-assets with timestamp metadata and source tracking.
     - **Exposed Service Nodes (Right Branch)**: Color-coded port nodes with dynamic visual alert states (crimson glow and pulsing animation for critical CVEs, amber for warnings, emerald for hardened/secure endpoints).
   - Interactive **Asset Telemetry Inspector Drawer**: Inspect raw service banners, CVE details, and remediation steps.
   - **JSON Threat Dossier Export**: One-click export for incident response reporting.

4. **Resilient Data Contract Model**:
   - Strict Pydantic v2 schemas (`backend/app/schemas.py`) ensuring zero frontend crashes due to missing or null attributes by supplying safe fallback variables (`"Unknown"`).

---

## 📁 Repository Structure

```
AetherMap-OSINT/
├── backend/
│   ├── app/
│   │   ├── __init__.py         # Package initialization
│   │   ├── main.py             # FastAPI server, route definitions & CORS security rules
│   │   ├── engines.py          # Asynchronous HTTPX reconnaissance hooks & Shodan/CVE simulator
│   │   └── schemas.py          # Pydantic data contract validation models
│   └── requirements.txt        # Pinned Python dependencies (fastapi, uvicorn, httpx, pydantic)
├── frontend/
│   ├── src/
│   │   ├── App.jsx             # Main reactive threat mapper UI with ReactFlow canvas
│   │   ├── index.css           # Tailwind directives & cyberpunk dark mode styles
│   │   └── main.jsx            # React 18 DOM mount point
│   ├── package.json            # Node.js dependencies (@xyflow/react, tailwindcss, lucide-react, vite)
│   ├── tailwind.config.js      # Custom theme colors, keyframes & alert animations
│   ├── postcss.config.js       # PostCSS Tailwind build pipeline
│   ├── vite.config.js          # Vite local development configuration & reverse proxy
│   └── index.html              # HTML wrapper with JetBrains Mono & Inter typography
├── .gitignore                  # Production Git ignore rules
└── README.md                   # Complete DevSecOps architectural documentation
```

---

## 🛠️ Quickstart & Local Setup

### Prerequisites
- **Python**: 3.11 or higher
- **Node.js**: 18.x or 20.x LTS
- **Git**: Installed and configured

---

### Step 1: Start the Backend Server

```bash
# Navigate to backend directory
cd backend

# Create and activate Python virtual environment
python3 -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start FastAPI development server with hot-reload
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

* Backend API will be live at: `http://localhost:8000`
* Interactive OpenAPI Swagger Documentation: `http://localhost:8000/docs`
* ReDoc Specification: `http://localhost:8000/redoc`

---

### Step 2: Start the Frontend Application

Open a new terminal window:

```bash
# Navigate to frontend directory
cd frontend

# Install Node dependencies
npm install

# Start Vite development server
npm run dev
```

* Frontend Application will be live at: `http://localhost:5173`

---

## 📡 REST API Reference

### 1. Root Health Check
* **Endpoint**: `GET /`
* **Response**:
```json
{
  "service": "AetherMap-OSINT",
  "status": "OPERATIONAL",
  "version": "1.0.0",
  "engines": {
    "crt_sh": "active",
    "shodan_simulator": "active",
    "cve_correlator": "active"
  }
}
```

### 2. Execute Reconnaissance
* **Endpoint**: `POST /api/recon`
* **Headers**: `Content-Type: application/json`
* **Payload**:
```json
{
  "domain": "tesla.com"
}
```

* **Sample Response**:
```json
{
  "target_domain": "tesla.com",
  "root_ip": "104.20.73.12",
  "timestamp": "2026-09-02T16:58:00.000Z",
  "threat_score": 88,
  "risk_level": "CRITICAL",
  "subdomains": [
    {
      "name": "api.tesla.com",
      "ip": "104.20.73.12",
      "status": "Active",
      "source": "crt.sh",
      "last_seen": "2024-03-01T00:00:00"
    }
  ],
  "services": [
    {
      "port": 8080,
      "protocol": "tcp",
      "service_name": "HTTP-Alt (Apache Tomcat)",
      "product": "Apache Tomcat",
      "version": "9.0.41",
      "banner": "Log4j-Core 2.14.1 Active",
      "status": "open",
      "vulnerabilities": [
        {
          "cve_id": "CVE-2021-44228",
          "severity": "CRITICAL",
          "cvss_score": 10.0,
          "description": "Log4Shell: JNDI injection leading to unauthenticated RCE.",
          "service": "Apache Tomcat / Log4j",
          "port": 8080,
          "remediation": "Upgrade Log4j to >= 2.17.1."
        }
      ]
    }
  ],
  "vulnerability_summary": {
    "critical": 4,
    "high": 1,
    "medium": 1,
    "low": 0,
    "total": 6
  },
  "metadata": {
    "execution_time_ms": 118.4,
    "sources_queried": [
      "Certificate Transparency (crt.sh)",
      "Shodan Network Intelligence (Simulator)",
      "Asynchronous DNS Resolver"
    ],
    "dns_resolved": true,
    "crt_sh_status": "Success",
    "shodan_status": "Success (Simulated Shodan Fingerprint)"
  }
}
```

---

## 🧮 Threat Risk Scoring Methodology

Composite Threat Scores are calculated via a weighted risk index (0–100):

$$\text{Threat Score} = \min\left(100, \, (N_{\text{crit}} \times 28) + (N_{\text{high}} \times 15) + (N_{\text{med}} \times 6) + (N_{\text{low}} \times 2) + 2 S_{\text{ports}} + \min(S_{\text{subs}}, 10)\right)$$

| Score Range | Risk Tier | Color Indicator | Recommended Action |
| :--- | :--- | :--- | :--- |
| **80 – 100** | `CRITICAL` | 🔴 Glowing Red (Pulse) | Immediate incident triage & patch deployment required |
| **60 – 79** | `HIGH` | 🟠 Warning Amber | Scheduled vulnerability remediation within 48h |
| **35 – 59** | `MEDIUM` | 🟡 Yellow | Review access control lists and ingress rules |
| **1 – 34** | `LOW` | 🔵 Cyan | Routine maintenance and configuration hardening |
| **0** | `CLEAN` | 🟢 Emerald | Target exhibits zero exposed CVE signatures |

---

## 🛡️ Security & Responsible Disclosure Disclaimer

> **DISCLAIMER**: *AetherMap-OSINT is engineered strictly for authorized security research, defensive posture auditing, penetration testing within scope, and educational demonstration. Always obtain explicit written authorization before conducting active intelligence gathering against third-party networks.*

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for more information.

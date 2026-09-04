"""Synthetic findings used only by the explicit demo endpoint."""
from app.schemas import PortService, SeverityLevel, Vulnerability


def demo_services() -> list[PortService]:
    return [
        PortService(port=22, service_name="SSH", product="OpenSSH", version="8.2p1", banner="DEMO: SSH-2.0-OpenSSH_8.2p1", status="demo", vulnerabilities=[
            Vulnerability(cve_id="CVE-2023-38408", severity=SeverityLevel.HIGH, cvss_score=9.8, description="Synthetic demonstration finding. Confirm exact package and configuration before treating it as applicable.", service="SSH", port=22, confidence="demo", source="NVD")
        ]),
        PortService(port=443, service_name="HTTPS", product="TLS endpoint", version="demo", banner="DEMO: HTTPS endpoint", status="demo"),
        PortService(port=8080, service_name="HTTP", product="Apache Tomcat", version="9.0.41", banner="DEMO: Apache-Coyote/1.1", status="demo", vulnerabilities=[
            Vulnerability(cve_id="CVE-2021-44228", severity=SeverityLevel.CRITICAL, cvss_score=10.0, description="Synthetic demonstration finding. Applicability requires verified dependency and configuration.", service="HTTP", port=8080, confidence="demo", source="NVD")
        ]),
    ]

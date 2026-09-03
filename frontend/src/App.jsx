import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  ReactFlow,
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  Handle,
  Position,
  MarkerType,
} from '@xyflow/react';
import axios from 'axios';
import {
  ShieldAlert,
  ShieldCheck,
  Radar,
  Network,
  Cpu,
  AlertTriangle,
  Terminal,
  Activity,
  Download,
  Search,
  ExternalLink,
  Layers,
  Lock,
  Unlock,
  X,
  RefreshCw,
  Server,
  Globe,
  Radio,
  Clock,
  CheckCircle2,
  ChevronRight,
  Flame,
} from 'lucide-react';

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL !== undefined
    ? import.meta.env.VITE_API_BASE_URL
    : typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
    ? 'http://localhost:8000'
    : '';

/* =========================================================================
   CUSTOM REACTFLOW NODE COMPONENTS
   ========================================================================= */

// 1. Root Domain Hub Node (Central Radar Node)
const RootNode = ({ data }) => {
  return (
    <div className="relative group cursor-pointer">
      {/* Outer Pulse Rings */}
      <div className="absolute -inset-2 bg-gradient-to-r from-cyan-500/30 to-blue-500/30 rounded-2xl blur-md group-hover:blur-lg transition-all animate-glow-pulse" />
      
      <div className="relative bg-[#0a0f1d] border-2 border-cyan-500/80 hover:border-cyan-400 rounded-xl p-5 shadow-2xl min-w-[280px] text-left transition-all">
        {/* Handles */}
        <Handle
          type="source"
          position={Position.Left}
          id="subdomains"
          className="!bg-cyan-400 !w-3 !h-3 !border-2 !border-[#0a0f1d]"
        />
        <Handle
          type="source"
          position={Position.Right}
          id="services"
          className="!bg-cyan-400 !w-3 !h-3 !border-2 !border-[#0a0f1d]"
        />

        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 bg-cyan-950/80 border border-cyan-500/50 rounded-lg text-cyan-400">
              <Radar className="w-5 h-5 animate-radar-sweep" />
            </div>
            <div>
              <span className="text-[10px] tracking-wider uppercase font-mono text-cyan-400 font-semibold block">
                PRIMARY TARGET HUB
              </span>
              <h2 className="text-base font-bold text-white tracking-wide truncate max-w-[170px]">
                {data.label || 'Unknown Target'}
              </h2>
            </div>
          </div>
          <span className="flex h-2.5 w-2.5 relative">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
          </span>
        </div>

        <div className="mt-3 space-y-1.5 font-mono text-xs text-slate-400">
          <div className="flex items-center justify-between">
            <span className="text-slate-500">IP ADDRESS</span>
            <span className="text-cyan-300 font-medium">{data.ip || 'Unknown'}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-500">THREAT INDEX</span>
            <span className={`font-bold px-1.5 py-0.5 rounded text-[11px] ${
              data.threatScore >= 75 ? 'bg-red-950 text-red-400 border border-red-800' :
              data.threatScore >= 40 ? 'bg-amber-950 text-amber-400 border border-amber-800' :
              'bg-emerald-950 text-emerald-400 border border-emerald-800'
            }`}>
              {data.threatScore ?? 0}/100 ({data.riskLevel || 'UNKNOWN'})
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

// 2. Subdomain Leaf Node (Left Branch)
const SubdomainNode = ({ data }) => {
  return (
    <div className="relative group cursor-pointer">
      <div className="bg-[#0b1329]/90 hover:bg-[#0f1b38] border border-cyan-900/60 hover:border-cyan-500/80 rounded-lg p-3.5 shadow-lg min-w-[240px] text-left transition-all duration-200">
        <Handle
          type="target"
          position={Position.Right}
          className="!bg-cyan-500 !w-2.5 !h-2.5 !border-2 !border-[#0b1329]"
        />

        <div className="flex items-center space-x-2.5">
          <div className="p-1.5 bg-cyan-950/60 border border-cyan-800/40 rounded text-cyan-400 flex-shrink-0">
            <Globe className="w-4 h-4" />
          </div>
          <div className="overflow-hidden">
            <div className="flex items-center space-x-1.5">
              <span className="text-[10px] uppercase font-mono text-cyan-500 font-semibold">ASSET</span>
              <span className="text-[9px] px-1 py-0.2 bg-slate-800 text-slate-400 rounded font-mono">
                {data.source || 'crt.sh'}
              </span>
            </div>
            <h4 className="text-xs font-semibold text-slate-200 truncate font-mono" title={data.label}>
              {data.label || 'subdomain.unknown'}
            </h4>
          </div>
        </div>

        <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
          <span className="text-slate-500">IP: {data.ip || 'Dynamic'}</span>
          <span className="text-emerald-400 flex items-center gap-1 text-[10px]">
            <CheckCircle2 className="w-3 h-3" /> Active
          </span>
        </div>
      </div>
    </div>
  );
};

// 3. Exposed Port / Service Node (Right Branch - Vulnerability Highlighted)
const ServiceNode = ({ data }) => {
  const hasVulns = data.vulnerabilities && data.vulnerabilities.length > 0;
  const hasCritical = hasVulns && data.vulnerabilities.some(v => v.severity === 'CRITICAL');
  const hasHigh = hasVulns && data.vulnerabilities.some(v => v.severity === 'HIGH');

  const containerClasses = hasCritical
    ? 'bg-red-950/80 border-2 border-red-500 text-red-100 animate-pulse-danger'
    : hasHigh || hasVulns
    ? 'bg-amber-950/70 border border-amber-500 text-amber-100 animate-pulse-warning'
    : 'bg-[#0a1224]/90 border border-emerald-500/50 hover:border-emerald-400 text-slate-200';

  const badgeClasses = hasCritical
    ? 'bg-red-500 text-white'
    : hasHigh || hasVulns
    ? 'bg-amber-500 text-black'
    : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40';

  return (
    <div className="relative group cursor-pointer">
      <div className={`rounded-xl p-4 shadow-xl min-w-[260px] text-left transition-all duration-200 ${containerClasses}`}>
        <Handle
          type="target"
          position={Position.Left}
          className={`!w-2.5 !h-2.5 !border-2 !border-[#0a0f1d] ${
            hasCritical ? '!bg-red-500' : hasVulns ? '!bg-amber-500' : '!bg-emerald-400'
          }`}
        />

        <div className="flex items-start justify-between">
          <div className="flex items-center space-x-2.5">
            <div className={`p-2 rounded-lg ${
              hasCritical ? 'bg-red-900/60 border border-red-400/60 text-red-300' :
              hasVulns ? 'bg-amber-900/60 border border-amber-400/60 text-amber-300' :
              'bg-emerald-950/60 border border-emerald-500/40 text-emerald-400'
            }`}>
              {hasCritical ? <ShieldAlert className="w-5 h-5" /> :
               hasVulns ? <AlertTriangle className="w-5 h-5" /> :
               <Lock className="w-5 h-5" />}
            </div>
            <div>
              <div className="flex items-center space-x-1.5">
                <span className="text-xs font-mono font-bold tracking-wider">
                  PORT {data.port || 0}
                </span>
                <span className="text-[10px] uppercase font-mono px-1 bg-black/40 rounded text-slate-400">
                  {data.protocol || 'TCP'}
                </span>
              </div>
              <h4 className="text-xs font-semibold truncate max-w-[140px] text-white">
                {data.serviceName || 'Unknown Service'}
              </h4>
            </div>
          </div>

          <span className={`text-[9px] font-mono font-bold uppercase px-1.5 py-0.5 rounded ${badgeClasses}`}>
            {hasCritical ? 'CRITICAL' : hasVulns ? 'EXPOSED' : 'SECURE'}
          </span>
        </div>

        {/* Product / Version Line */}
        <div className="mt-2.5 text-[11px] font-mono text-slate-400 truncate">
          {data.product || 'Unknown Product'} {data.version ? `v${data.version}` : ''}
        </div>

        {/* Vulnerability Badges List */}
        {hasVulns && (
          <div className="mt-2.5 pt-2 border-t border-red-900/50 space-y-1">
            {data.vulnerabilities.map((v, i) => (
              <div key={i} className="flex items-center justify-between text-[10px] font-mono bg-black/40 px-2 py-1 rounded">
                <span className="font-bold text-red-400">{v.cve_id}</span>
                <span className="text-red-300 font-semibold">CVSS {v.cvss_score?.toFixed(1) || '0.0'}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

// ReactFlow Node Types mapping
const nodeTypes = {
  rootNode: RootNode,
  subdomainNode: SubdomainNode,
  serviceNode: ServiceNode,
};

/* =========================================================================
   SAMPLE DATA FALLBACK (Resilience Engine)
   ========================================================================= */
const SAMPLE_RECON_DATA = {
  target_domain: "tesla.com",
  root_ip: "104.20.73.12",
  timestamp: new Date().toISOString(),
  threat_score: 88,
  risk_level: "CRITICAL",
  vulnerability_summary: {
    critical: 4,
    high: 1,
    medium: 1,
    low: 0,
    total: 6,
  },
  metadata: {
    execution_time_ms: 124.5,
    sources_queried: ["Certificate Transparency (crt.sh)", "Shodan Network Intelligence (Simulator)", "Asynchronous DNS Resolver"],
    dns_resolved: true,
    crt_sh_status: "Success",
    shodan_status: "Success (Simulated Shodan Fingerprint)",
  },
  subdomains: [
    { name: "api.tesla.com", ip: "104.20.73.12", status: "Active", source: "crt.sh", last_seen: "2024-03-01T00:00:00" },
    { name: "auth.tesla.com", ip: "104.20.73.14", status: "Active", source: "crt.sh", last_seen: "2024-01-20T08:15:00" },
    { name: "vpn.tesla.com", ip: "198.51.100.4", status: "Active", source: "crt.sh", last_seen: "2024-02-15T12:30:00" },
    { name: "fleet.tesla.com", ip: "104.20.74.8", status: "Active", source: "crt.sh", last_seen: "2024-04-10T11:00:00" },
    { name: "staging.tesla.com", ip: "198.51.100.99", status: "Active", source: "crt.sh", last_seen: "2024-04-05T19:20:00" },
    { name: "energy.tesla.com", ip: "104.20.73.15", status: "Active", source: "crt.sh", last_seen: "2024-03-15T09:00:00" },
    { name: "admin.tesla.com", ip: "198.51.100.12", status: "Active", source: "crt.sh", last_seen: "2024-03-28T11:10:00" },
  ],
  services: [
    {
      port: 22,
      protocol: "tcp",
      service_name: "OpenSSH",
      product: "OpenSSH",
      version: "8.2p1 Ubuntu",
      banner: "SSH-2.0-OpenSSH_8.2p1",
      status: "open",
      vulnerabilities: [
        {
          cve_id: "CVE-2023-38408",
          severity: "CRITICAL",
          cvss_score: 9.8,
          description: "Condition in ssh-agent PKCS#11 provider enables remote code execution via forwarded agent socket.",
          service: "OpenSSH",
          port: 22,
          remediation: "Upgrade OpenSSH to version 9.3p2 or newer; disable ssh-agent forwarding on untrusted bastion hosts."
        }
      ]
    },
    {
      port: 80,
      protocol: "tcp",
      service_name: "HTTP",
      product: "nginx",
      version: "1.18.0",
      banner: "HTTP/1.1 301 Moved Permanently",
      status: "open",
      vulnerabilities: [
        {
          cve_id: "CVE-2021-23017",
          severity: "HIGH",
          cvss_score: 7.7,
          description: "1-byte memory overwrite in nginx DNS resolver enables off-by-one buffer overflow.",
          service: "HTTP / nginx",
          port: 80,
          remediation: "Upgrade nginx to 1.20.1 or 1.21.0; enforce strict HTTPS redirects and HSTS policies."
        }
      ]
    },
    {
      port: 443,
      protocol: "tcp",
      service_name: "HTTPS",
      product: "Envoy Proxy",
      version: "TLSv1.3",
      banner: "HTTP/2 200 OK Server: envoy",
      status: "open",
      vulnerabilities: []
    },
    {
      port: 8080,
      protocol: "tcp",
      service_name: "HTTP-Alt (Apache Tomcat)",
      product: "Apache Tomcat",
      version: "9.0.41",
      banner: "Log4j-Core 2.14.1 Active",
      status: "open",
      vulnerabilities: [
        {
          cve_id: "CVE-2021-44228",
          severity: "CRITICAL",
          cvss_score: 10.0,
          description: "Log4Shell: Apache Log4j2 JNDI features used in configuration do not protect against attacker-controlled LDAP.",
          service: "Apache Tomcat / Log4j",
          port: 8080,
          remediation: "Immediately upgrade Log4j to >= 2.17.1 or set log4j2.formatMsgNoLookups=true system flag."
        },
        {
          cve_id: "CVE-2022-22965",
          severity: "CRITICAL",
          cvss_score: 9.8,
          description: "Spring4Shell: Spring Framework RCE via Data Binding parameter manipulation.",
          service: "Spring MVC",
          port: 8080,
          remediation: "Upgrade Spring Framework to 5.3.18 / 5.2.20 or newer."
        }
      ]
    },
    {
      port: 6379,
      protocol: "tcp",
      service_name: "Redis Server",
      product: "Redis Key-Value Store",
      version: "6.0.16",
      banner: "-DENIED Redis is running in protected mode",
      status: "open",
      vulnerabilities: [
        {
          cve_id: "CVE-2022-0543",
          severity: "CRITICAL",
          cvss_score: 10.0,
          description: "Debian/Ubuntu Redis packaging Lua sandbox escape vulnerability leading to arbitrary code execution.",
          service: "Redis",
          port: 6379,
          remediation: "Apply vendor patch for lua-cjson library; bind Redis exclusively to localhost / internal VPC."
        }
      ]
    },
    {
      port: 8443,
      protocol: "tcp",
      service_name: "HTTPS-Alt (Admin API)",
      product: "NodeJS / Express",
      version: "4.17.1",
      banner: "X-Powered-By: Express",
      status: "open",
      vulnerabilities: [
        {
          cve_id: "CVE-2022-24999",
          severity: "MEDIUM",
          cvss_score: 5.3,
          description: "Express body-parser prototype pollution via unvalidated JSON keys.",
          service: "Express Gateway",
          port: 8443,
          remediation: "Update body-parser to version 1.20.0 or higher."
        }
      ]
    }
  ]
};

/* =========================================================================
   MAIN APPLICATION COMPONENT
   ========================================================================= */
export default function App() {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  
  const [targetDomain, setTargetDomain] = useState('tesla.com');
  const [loading, setLoading] = useState(false);
  const [reconData, setReconData] = useState(SAMPLE_RECON_DATA);
  const [selectedItem, setSelectedItem] = useState(null);
  const [backendOnline, setBackendOnline] = useState(true);
  const [errorMessage, setErrorMessage] = useState(null);

  // Preset domains for rapid demonstration
  const PRESET_DOMAINS = ['tesla.com', 'uber.com', 'github.com', 'defense.gov', 'target.corp'];

  /* -------------------------------------------------------------------------
     GRAPH GENERATOR: Bipartite Layout (Target Center, Subdomains Left, Ports Right)
     ------------------------------------------------------------------------- */
  const buildGraphFromData = useCallback((data) => {
    if (!data) return;

    const newNodes = [];
    const newEdges = [];

    // 1. Central Root Domain Node
    const rootNodeId = 'root-target';
    newNodes.push({
      id: rootNodeId,
      type: 'rootNode',
      position: { x: 0, y: 0 },
      data: {
        label: data.target_domain || 'Unknown Target',
        ip: data.root_ip || 'Unknown',
        threatScore: data.threat_score ?? 0,
        riskLevel: data.risk_level || 'UNKNOWN',
        raw: data,
      },
    });

    // 2. Subdomains arrayed on the Left Side
    const subdomains = data.subdomains || [];
    const subCount = subdomains.length;
    const subSpacingY = 90;
    const subStartX = -480;
    const subStartY = -((subCount - 1) * subSpacingY) / 2;

    subdomains.forEach((sub, idx) => {
      const nodeId = `sub-${idx}`;
      const posY = subStartY + idx * subSpacingY;

      newNodes.push({
        id: nodeId,
        type: 'subdomainNode',
        position: { x: subStartX, y: posY },
        data: {
          label: sub.name || 'subdomain.unknown',
          ip: sub.ip || 'Unknown',
          source: sub.source || 'crt.sh',
          lastSeen: sub.last_seen || 'Unknown',
          raw: sub,
        },
      });

      // Edge from Central Root (left handle) to Subdomain (right handle)
      newEdges.push({
        id: `edge-root-${nodeId}`,
        source: rootNodeId,
        sourceHandle: 'subdomains',
        target: nodeId,
        animated: true,
        style: { stroke: '#06b6d4', strokeWidth: 1.5, strokeDasharray: '5,5' },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: '#06b6d4',
          width: 15,
          height: 15,
        },
      });
    });

    // 3. Exposed Services / Ports arrayed on the Right Side
    const services = data.services || [];
    const servCount = services.length;
    const servSpacingY = 135;
    const servStartX = 480;
    const servStartY = -((servCount - 1) * servSpacingY) / 2;

    services.forEach((serv, idx) => {
      const nodeId = `serv-${idx}`;
      const posY = servStartY + idx * servSpacingY;
      const hasVulns = serv.vulnerabilities && serv.vulnerabilities.length > 0;
      const hasCritical = hasVulns && serv.vulnerabilities.some(v => v.severity === 'CRITICAL');

      newNodes.push({
        id: nodeId,
        type: 'serviceNode',
        position: { x: servStartX, y: posY },
        data: {
          port: serv.port,
          protocol: serv.protocol || 'tcp',
          serviceName: serv.service_name || 'Unknown',
          product: serv.product || 'Unknown',
          version: serv.version || '',
          banner: serv.banner || '',
          vulnerabilities: serv.vulnerabilities || [],
          raw: serv,
        },
      });

      // Edge from Central Root (right handle) to Service (left handle)
      const edgeColor = hasCritical ? '#ef4444' : hasVulns ? '#f59e0b' : '#10b981';

      newEdges.push({
        id: `edge-root-${nodeId}`,
        source: rootNodeId,
        sourceHandle: 'services',
        target: nodeId,
        animated: hasVulns,
        style: {
          stroke: edgeColor,
          strokeWidth: hasCritical ? 2.5 : 1.8,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: edgeColor,
          width: 15,
          height: 15,
        },
      });
    });

    setNodes(newNodes);
    setEdges(newEdges);
  }, [setNodes, setEdges]);

  /* -------------------------------------------------------------------------
     FETCH RECON INTELLIGENCE
     ------------------------------------------------------------------------- */
  const handleInitiateRecon = async (domainToScan) => {
    const domain = (domainToScan || targetDomain).trim();
    if (!domain) return;

    setLoading(true);
    setErrorMessage(null);
    setSelectedItem(null);

    try {
      // Execute non-blocking POST to FastAPI /api/recon
      const response = await axios.post(`${API_BASE_URL}/api/recon`, { domain }, { timeout: 15000 });
      if (response.data) {
        setReconData(response.data);
        buildGraphFromData(response.data);
        setBackendOnline(true);
      }
    } catch (err) {
      console.warn('Backend API connection warning:', err.message);
      // Fallback resilience for seamless demo / offline mode
      setBackendOnline(false);
      setErrorMessage(`Backend connection unreached (${err.message}). Rendering simulated attack surface topology.`);
      
      const simulatedData = {
        ...SAMPLE_RECON_DATA,
        target_domain: domain,
        timestamp: new Date().toISOString(),
      };
      setReconData(simulatedData);
      buildGraphFromData(simulatedData);
    } finally {
      setLoading(false);
    }
  };

  // Initial load
  useEffect(() => {
    handleInitiateRecon('tesla.com');
  }, []);

  // Handle Node Selection for Inspector Drawer
  const onNodeClick = useCallback((event, node) => {
    setSelectedItem(node.data);
  }, []);

  // Export JSON Report
  const exportDossier = () => {
    const jsonStr = JSON.stringify(reconData, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `AetherMap_OSINT_${reconData.target_domain}_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col h-screen w-screen bg-[#050811] text-slate-100 overflow-hidden select-none">
      {/* -------------------------------------------------------------------
          TOP NAVIGATION & COMMAND BAR
          ------------------------------------------------------------------- */}
      <header className="h-16 bg-[#0a0f1d]/90 border-b border-slate-800/90 px-6 flex items-center justify-between z-20 backdrop-blur-md">
        {/* Brand Logo & Identity */}
        <div className="flex items-center space-x-3">
          <div className="relative">
            <div className="p-2 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-lg shadow-lg shadow-cyan-500/20 text-black">
              <Radar className="w-5 h-5 text-slate-950 font-bold animate-pulse" />
            </div>
            <span className="absolute -bottom-1 -right-1 flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
            </span>
          </div>

          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-base font-extrabold tracking-wider bg-gradient-to-r from-cyan-400 via-sky-300 to-blue-500 bg-clip-text text-transparent">
                AETHERMAP<span className="text-slate-400 font-normal"> // OSINT</span>
              </h1>
              <span className="text-[10px] font-mono px-1.5 py-0.5 bg-cyan-950/80 border border-cyan-700/60 text-cyan-300 rounded font-bold">
                v1.0.0 PRO
              </span>
            </div>
            <p className="text-[10px] font-mono text-slate-500 tracking-tight">
              AUTOMATED ATTACK SURFACE & THREAT TOPOLOGY MAPPER
            </p>
          </div>
        </div>

        {/* Search & Action Input Bar */}
        <div className="flex items-center space-x-3 max-w-xl w-full mx-6">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleInitiateRecon(targetDomain);
            }}
            className="flex-1 relative flex items-center"
          >
            <div className="absolute left-3 text-slate-500 pointer-events-none">
              <Search className="w-4 h-4 text-cyan-400" />
            </div>
            <input
              type="text"
              value={targetDomain}
              onChange={(e) => setTargetDomain(e.target.value)}
              placeholder="Enter Target Domain (e.g. tesla.com, uber.com)..."
              className="w-full bg-[#050811] border border-slate-700 focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 pl-9 pr-24 py-2 rounded-lg text-xs font-mono text-white placeholder-slate-500 transition-all outline-none"
            />
            <button
              type="submit"
              disabled={loading}
              className="absolute right-1 px-3 py-1.2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black font-mono font-bold text-xs rounded-md flex items-center space-x-1.5 shadow-md shadow-cyan-500/20 transition-all disabled:opacity-50"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>SCANNING</span>
                </>
              ) : (
                <>
                  <Radio className="w-3.5 h-3.5" />
                  <span>SCAN</span>
                </>
              )}
            </button>
          </form>

          {/* Quick Preset Selector Pills */}
          <div className="hidden xl:flex items-center space-x-1 font-mono text-[11px]">
            <span className="text-slate-500 mr-1">PRESETS:</span>
            {PRESET_DOMAINS.map((domain) => (
              <button
                key={domain}
                onClick={() => {
                  setTargetDomain(domain);
                  handleInitiateRecon(domain);
                }}
                className="px-2 py-1 bg-slate-900 hover:bg-cyan-950 border border-slate-800 hover:border-cyan-700 text-slate-300 hover:text-cyan-300 rounded transition-all"
              >
                {domain}
              </button>
            ))}
          </div>
        </div>

        {/* Global Controls & Status */}
        <div className="flex items-center space-x-3">
          <button
            onClick={exportDossier}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 hover:border-slate-600 text-slate-300 rounded-lg text-xs font-mono font-medium transition-all"
            title="Export Threat Intelligence Dossier as JSON"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>EXPORT DOSSIER</span>
          </button>

          <div className="flex items-center space-x-2 pl-3 border-l border-slate-800 font-mono text-[11px]">
            <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-slate-400">{backendOnline ? 'BACKEND ONLINE' : 'SIMULATED FEED'}</span>
          </div>
        </div>
      </header>

      {/* -------------------------------------------------------------------
          TOP THREAT METRIC HUD STRIP
          ------------------------------------------------------------------- */}
      <div className="bg-[#080d1a] border-b border-slate-800/70 px-6 py-2.5 flex flex-wrap items-center justify-between text-xs z-10 font-mono">
        <div className="flex items-center space-x-6">
          {/* Target Domain Indicator */}
          <div className="flex items-center space-x-2">
            <span className="text-slate-500">TARGET:</span>
            <span className="font-bold text-cyan-400 text-sm">{reconData.target_domain}</span>
            <span className="text-slate-500 text-[11px]">({reconData.root_ip || 'Unknown IP'})</span>
          </div>

          {/* Threat Risk Index Gauge */}
          <div className="flex items-center space-x-2 pl-4 border-l border-slate-800">
            <span className="text-slate-500">THREAT SCORE:</span>
            <div className="flex items-center space-x-1.5">
              <span className={`font-extrabold text-sm px-2 py-0.5 rounded ${
                reconData.threat_score >= 75 ? 'bg-red-950 text-red-400 border border-red-800' :
                reconData.threat_score >= 40 ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                'bg-emerald-950 text-emerald-400 border border-emerald-800'
              }`}>
                {reconData.threat_score}/100
              </span>
              <span className="text-[11px] font-bold text-slate-300">
                [{reconData.risk_level}]
              </span>
            </div>
          </div>

          {/* Subdomains Count */}
          <div className="flex items-center space-x-1.5 pl-4 border-l border-slate-800">
            <Globe className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-500">SUBDOMAINS:</span>
            <span className="font-bold text-white">{reconData.subdomains?.length || 0}</span>
          </div>

          {/* Open Ports Count */}
          <div className="flex items-center space-x-1.5 pl-4 border-l border-slate-800">
            <Server className="w-3.5 h-3.5 text-blue-400" />
            <span className="text-slate-500">EXPOSED PORTS:</span>
            <span className="font-bold text-white">{reconData.services?.length || 0}</span>
          </div>

          {/* Critical CVEs Count */}
          <div className="flex items-center space-x-1.5 pl-4 border-l border-slate-800">
            <Flame className="w-3.5 h-3.5 text-red-500 animate-pulse" />
            <span className="text-slate-500">CRITICAL CVEs:</span>
            <span className="font-bold text-red-400">{reconData.vulnerability_summary?.critical || 0}</span>
          </div>
        </div>

        {/* Scan Latency / Diagnostics */}
        <div className="flex items-center space-x-4 text-slate-500 text-[11px]">
          <div className="flex items-center space-x-1">
            <Clock className="w-3 h-3 text-slate-400" />
            <span>LATENCY: {reconData.metadata?.execution_time_ms || 0}ms</span>
          </div>
          <div className="flex items-center space-x-1">
            <Activity className="w-3 h-3 text-emerald-400" />
            <span>SOURCES: {reconData.metadata?.sources_queried?.length || 3} ACTIVE</span>
          </div>
        </div>
      </div>

      {/* -------------------------------------------------------------------
          MAIN INTERACTIVE CANVAS (REACTFLOW)
          ------------------------------------------------------------------- */}
      <div className="flex-1 relative w-full h-full bg-[#050811] cyber-grid">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={onNodeClick}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.25 }}
          minZoom={0.2}
          maxZoom={1.8}
        >
          <Background color="#1e293b" gap={24} size={1} />
          <Controls className="!bg-[#0a0f1d] !border-slate-800 text-slate-300" />
          <MiniMap
            nodeColor={(n) => {
              if (n.type === 'rootNode') return '#06b6d4';
              if (n.type === 'subdomainNode') return '#38bdf8';
              if (n.data?.vulnerabilities?.some(v => v.severity === 'CRITICAL')) return '#ef4444';
              return '#10b981';
            }}
            maskColor="rgba(5, 8, 17, 0.8)"
            className="!border-slate-800"
          />
        </ReactFlow>

        {/* Toast Warning / Notice if applicable */}
        {errorMessage && (
          <div className="absolute top-4 left-6 z-30 max-w-md bg-amber-950/90 border border-amber-500/80 rounded-lg p-3 text-xs font-mono text-amber-200 shadow-xl flex items-start space-x-2">
            <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <span className="font-bold">RESILIENCE TRIGGER:</span> {errorMessage}
            </div>
            <button onClick={() => setErrorMessage(null)} className="text-amber-400 hover:text-white">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Legend Overlay */}
        <div className="absolute bottom-6 left-6 z-10 bg-[#0a0f1d]/90 border border-slate-800 rounded-lg p-3 shadow-2xl backdrop-blur-md font-mono text-[11px] space-y-1.5">
          <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-1">
            TOPOLOGY MAP KEY
          </div>
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 shadow-sm shadow-cyan-400" />
            <span className="text-slate-300">Central Target Hub</span>
          </div>
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-sky-400" />
            <span className="text-slate-300">Discovered Subdomains (crt.sh)</span>
          </div>
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping" />
            <span className="text-red-400 font-semibold">Critical CVE Vulnerability</span>
          </div>
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
            <span className="text-slate-300">Hardened / Secure Service</span>
          </div>
        </div>

        {/* -----------------------------------------------------------------
            NODE DETAILS INSPECTOR DRAWER
            ----------------------------------------------------------------- */}
        {selectedItem && (
          <aside className="absolute top-4 right-4 bottom-4 w-96 z-30 bg-[#0a0f1d]/95 border border-slate-700/80 rounded-xl shadow-2xl backdrop-blur-xl flex flex-col overflow-hidden animate-in slide-in-from-right duration-200">
            {/* Drawer Header */}
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
              <div className="flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <h3 className="font-mono font-bold text-xs text-white uppercase tracking-wider">
                  ASSET TELEMETRY INSPECTOR
                </h3>
              </div>
              <button
                onClick={() => setSelectedItem(null)}
                className="p-1 text-slate-400 hover:text-white rounded hover:bg-slate-800 transition-all"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Drawer Scrollable Content */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4 font-mono text-xs">
              {/* Asset Identity Block */}
              <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3.5 space-y-2">
                <span className="text-[10px] font-bold text-slate-500 uppercase">IDENTIFIER</span>
                <div className="text-sm font-bold text-cyan-300 break-all">
                  {selectedItem.label || selectedItem.serviceName || 'Target Asset'}
                </div>
                {selectedItem.ip && (
                  <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-slate-800">
                    <span className="text-slate-500">IP ADDRESS:</span>
                    <span className="text-white font-medium">{selectedItem.ip}</span>
                  </div>
                )}
                {selectedItem.port && (
                  <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-slate-800">
                    <span className="text-slate-500">PORT / PROTOCOL:</span>
                    <span className="text-white font-medium">{selectedItem.port} / {selectedItem.protocol?.toUpperCase() || 'TCP'}</span>
                  </div>
                )}
                {selectedItem.source && (
                  <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-slate-800">
                    <span className="text-slate-500">DISCOVERY SOURCE:</span>
                    <span className="text-cyan-400">{selectedItem.source}</span>
                  </div>
                )}
              </div>

              {/* Banner / Fingerprint Block */}
              {selectedItem.banner && (
                <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 space-y-1.5">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">SERVICE BANNER CAPTURE</span>
                  <pre className="text-[10px] bg-[#050811] p-2.5 rounded border border-slate-800/80 text-emerald-400 whitespace-pre-wrap overflow-x-auto">
                    {selectedItem.banner}
                  </pre>
                </div>
              )}

              {/* Vulnerabilities Breakdown */}
              {selectedItem.vulnerabilities && selectedItem.vulnerabilities.length > 0 ? (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-bold text-red-400 uppercase tracking-wider flex items-center gap-1">
                      <ShieldAlert className="w-3.5 h-3.5" />
                      THREAT SIGNATURES ({selectedItem.vulnerabilities.length})
                    </span>
                  </div>

                  {selectedItem.vulnerabilities.map((vuln, idx) => (
                    <div
                      key={idx}
                      className="bg-red-950/40 border border-red-800/60 rounded-lg p-3.5 space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-red-300 text-xs">{vuln.cve_id}</span>
                        <span className="text-[10px] font-bold px-1.5 py-0.5 bg-red-900 text-red-200 rounded">
                          CVSS {vuln.cvss_score?.toFixed(1)} ({vuln.severity})
                        </span>
                      </div>

                      <p className="text-[11px] text-slate-300 leading-relaxed font-sans">
                        {vuln.description}
                      </p>

                      <div className="pt-2 border-t border-red-900/40">
                        <span className="text-[10px] font-bold text-amber-400 block mb-1">REMEDIATION GUIDANCE:</span>
                        <p className="text-[11px] text-slate-400 font-sans italic">
                          {vuln.remediation}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              ) : selectedItem.port ? (
                <div className="bg-emerald-950/30 border border-emerald-800/50 rounded-lg p-3 text-emerald-300 flex items-center space-x-2">
                  <ShieldCheck className="w-5 h-5 text-emerald-400 flex-shrink-0" />
                  <span className="text-[11px]">No active critical CVE signatures correlated with this endpoint.</span>
                </div>
              ) : null}
            </div>

            {/* Drawer Footer */}
            <div className="p-3 border-t border-slate-800 bg-slate-900/60 flex items-center justify-between text-[10px] font-mono text-slate-500">
              <span>AETHERMAP SECURITY ADVISORY</span>
              <button
                onClick={() => setSelectedItem(null)}
                className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-white rounded transition-all"
              >
                Close
              </button>
            </div>
          </aside>
        )}
      </div>
    </div>
  );
}

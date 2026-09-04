import React, { useCallback, useEffect, useState } from 'react';
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
  AlertTriangle,
  CheckCircle2,
  Download,
  ExternalLink,
  Globe,
  Lock,
  Radio,
  Radar,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  X,
  Zap,
} from 'lucide-react';

const API_BASE_URL = import.meta.env.VITE_API_URL || '';
const DEMO_ENDPOINT = `${API_BASE_URL.replace(/\/+$/, '')}/api/recon/sample`;

const sanitizeDomain = (raw) => {
  const clean = (raw || '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0].trim();
  return clean;
};

const RootNode = ({ data }) => (
  <div className="relative group">
    <div className="absolute -inset-2 bg-cyan-500/20 rounded-2xl blur-md" />
    <div className="relative bg-[#0a0f1d] border-2 border-cyan-500/80 rounded-xl p-5 shadow-2xl min-w-[280px]">
      <Handle type="source" position={Position.Left} id="subdomains" className="!bg-cyan-400 !w-3 !h-3" />
      <Handle type="source" position={Position.Right} id="services" className="!bg-cyan-400 !w-3 !h-3" />
      <div className="flex items-center gap-3 pb-3 border-b border-slate-800">
        <div className="p-2 bg-cyan-950 border border-cyan-500/50 rounded-lg text-cyan-400"><Radar className="w-5 h-5" /></div>
        <div className="min-w-0">
          <span className="text-[10px] tracking-wider uppercase font-mono text-cyan-400 font-semibold">PRIMARY TARGET</span>
          <h2 className="text-base font-bold text-white truncate">{data.label}</h2>
        </div>
      </div>
      <div className="mt-3 space-y-1.5 font-mono text-xs text-slate-400">
        <div className="flex justify-between gap-3"><span className="text-slate-500">IP</span><span className="text-cyan-300">{data.ip || 'Unknown'}</span></div>
        <div className="flex justify-between gap-3"><span className="text-slate-500">RISK</span><span className="text-white font-bold">{data.threatScore}/100 {data.riskLevel}</span></div>
        <div className="flex justify-between gap-3"><span className="text-slate-500">MODE</span><span className="text-amber-300">{data.findingsMode || 'passive'}</span></div>
      </div>
    </div>
  </div>
);

const SubdomainNode = ({ data }) => (
  <div className="relative bg-[#0b1329]/95 border border-cyan-900/60 rounded-lg p-3.5 shadow-lg min-w-[240px]">
    <Handle type="target" position={Position.Right} className="!bg-cyan-500 !w-2.5 !h-2.5" />
    <div className="flex items-center gap-2.5">
      <div className="p-1.5 bg-cyan-950/60 border border-cyan-800/40 rounded text-cyan-400"><Globe className="w-4 h-4" /></div>
      <div className="min-w-0">
        <div className="text-[10px] uppercase font-mono text-cyan-500">ASSET · {data.source || 'unknown source'}</div>
        <h4 className="text-xs font-semibold text-slate-200 truncate font-mono">{data.label}</h4>
      </div>
    </div>
    <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex justify-between text-[10px] font-mono">
      <span className="text-slate-500">IP: {data.ip || 'Unknown'}</span>
      <span className={data.status === 'resolved' ? 'text-emerald-400' : 'text-slate-500'}>{data.status || 'unknown'}</span>
    </div>
  </div>
);

const ServiceNode = ({ data }) => {
  const vulns = data.vulnerabilities || [];
  const critical = vulns.some((v) => v.severity === 'CRITICAL');
  const exposed = vulns.length > 0;
  const classes = critical
    ? 'bg-red-950/80 border-red-500'
    : exposed
      ? 'bg-amber-950/70 border-amber-500'
      : 'bg-[#0a1224]/90 border-emerald-500/50';
  return (
    <div className={`relative border rounded-xl p-4 shadow-xl min-w-[270px] ${classes}`}>
      <Handle type="target" position={Position.Left} className="!w-2.5 !h-2.5" />
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="p-2 rounded-lg bg-black/20">{critical ? <ShieldAlert className="w-5 h-5" /> : exposed ? <AlertTriangle className="w-5 h-5" /> : <Lock className="w-5 h-5" />}</div>
          <div className="min-w-0">
            <div className="text-xs font-mono font-bold">PORT {data.port}/{data.protocol || 'tcp'}</div>
            <h4 className="text-xs font-semibold text-white truncate">{data.serviceName || 'Unknown service'}</h4>
          </div>
        </div>
        <span className="text-[9px] font-mono font-bold uppercase px-1.5 py-0.5 rounded bg-black/30">{critical ? 'CRITICAL' : exposed ? 'FINDING' : 'OBSERVED'}</span>
      </div>
      <div className="mt-2.5 text-[10px] font-mono text-slate-400 truncate">{data.product || 'Unknown'} {data.version ? `v${data.version}` : ''}</div>
      {vulns.map((v) => (
        <div key={v.cve_id} className="mt-2.5 pt-2 border-t border-white/10">
          <div className="flex items-center justify-between text-[10px] font-mono"><span className="font-bold">{v.cve_id}</span><span>{v.cvss_score?.toFixed?.(1) ?? 'N/A'} · {v.severity}</span></div>
          <div className="mt-1 text-[9px] text-slate-400">confidence: {v.confidence || 'unknown'} · source: {v.source || 'unknown'}</div>
        </div>
      ))}
    </div>
  );
};

const nodeTypes = { rootNode: RootNode, subdomainNode: SubdomainNode, serviceNode: ServiceNode };

export default function App() {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [targetDomain, setTargetDomain] = useState('example.com');
  const [reconData, setReconData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState(null);
  const [selectedItem, setSelectedItem] = useState(null);
  const [notice, setNotice] = useState('');

  const buildGraphFromData = useCallback((data) => {
    const newNodes = [{
      id: 'root-target', type: 'rootNode', position: { x: 0, y: 0 },
      data: {
        label: data.target_domain, ip: data.root_ip, threatScore: data.threat_score,
        riskLevel: data.risk_level, findingsMode: data.metadata?.findings_mode,
      },
    }];
    const newEdges = [];

    const subdomains = data.subdomains || [];
    const subStartY = -((subdomains.length - 1) * 90) / 2;
    subdomains.forEach((sub, i) => {
      const id = `sub-${i}`;
      newNodes.push({ id, type: 'subdomainNode', position: { x: -500, y: subStartY + i * 90 }, data: { label: sub.name, ip: sub.ip, source: sub.source, status: sub.status } });
      newEdges.push({ id: `e-root-${id}`, source: 'root-target', sourceHandle: 'subdomains', target: id, animated: true, style: { stroke: '#06b6d4', strokeDasharray: '5,5' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#06b6d4' } });
    });

    const services = data.services || [];
    const serviceStartY = -((services.length - 1) * 150) / 2;
    services.forEach((service, i) => {
      const id = `service-${i}`;
      const vulns = service.vulnerabilities || [];
      const edgeColor = vulns.some((v) => v.severity === 'CRITICAL') ? '#ef4444' : vulns.length ? '#f59e0b' : '#10b981';
      newNodes.push({
        id, type: 'serviceNode', position: { x: 500, y: serviceStartY + i * 150 },
        data: { port: service.port, protocol: service.protocol, serviceName: service.service_name, product: service.product, version: service.version, vulnerabilities: vulns },
      });
      newEdges.push({ id: `e-root-${id}`, source: 'root-target', sourceHandle: 'services', target: id, animated: vulns.length > 0, style: { stroke: edgeColor, strokeWidth: 2 }, markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor } });
    });
    setNodes(newNodes);
    setEdges(newEdges);
  }, [setEdges, setNodes]);

  const scan = async (domainInput) => {
    const domain = sanitizeDomain(domainInput ?? targetDomain);
    if (!domain) return;
    setLoading(true);
    setErrorMessage(null);
    setNotice('');
    try {
      const endpoint = `${API_BASE_URL.replace(/\/+$/, '')}/api/recon`;
      const response = await axios.post(endpoint, { domain }, { timeout: 12000 });
      setReconData(response.data);
      buildGraphFromData(response.data);
      setTargetDomain(domain);
    } catch (err) {
      setErrorMessage(err?.response?.data?.detail || 'Backend unavailable. Use the explicit demo dataset instead.');
    } finally {
      setLoading(false);
    }
  };

  const loadDemo = async () => {
    setLoading(true);
    setErrorMessage(null);
    try {
      const response = await axios.get(DEMO_ENDPOINT || '/api/recon/sample', { timeout: 12000 });
      setReconData(response.data);
      buildGraphFromData(response.data);
      setTargetDomain(response.data.target_domain);
    } catch (err) {
      setErrorMessage(err?.response?.data?.detail || 'Demo endpoint unavailable.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadDemo(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const exportDossier = () => {
    if (!reconData) return;
    const blob = new Blob([JSON.stringify(reconData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `AetherMap_OSINT_${reconData.target_domain}_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col h-screen w-screen bg-[#050811] text-slate-100 overflow-hidden">
      <header className="h-16 bg-[#0a0f1d]/95 border-b border-slate-800 px-6 flex items-center justify-between gap-4 z-20">
        <div className="flex items-center gap-3 min-w-0">
          <div className="p-2 bg-cyan-500 rounded-lg text-black"><Radar className="w-5 h-5" /></div>
          <div className="min-w-0"><h1 className="text-base font-extrabold tracking-wider text-cyan-400">AETHERMAP<span className="text-slate-400 font-normal"> // OSINT</span></h1><p className="text-[10px] font-mono text-slate-500">AUTHORIZED ATTACK-SURFACE & THREAT TOPOLOGY MAPPER</p></div>
        </div>
        <form onSubmit={(e) => { e.preventDefault(); scan(targetDomain); }} className="flex-1 max-w-2xl relative flex items-center gap-2">
          <Search className="absolute left-3 w-4 h-4 text-cyan-400" />
          <input value={targetDomain} onChange={(e) => setTargetDomain(e.target.value)} placeholder="example.com" className="w-full bg-[#070d1d] border-2 border-slate-700 focus:border-cyan-400 rounded-xl pl-10 pr-24 py-2.5 font-mono text-white outline-none" />
          <button disabled={loading} className="absolute right-1.5 px-3 py-2 bg-cyan-500 text-black font-mono font-bold text-xs rounded-lg disabled:opacity-40">{loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : 'SCAN'}</button>
        </form>
        <div className="flex items-center gap-2">
          <button onClick={loadDemo} className="px-3 py-2 border border-amber-700 text-amber-300 rounded-lg text-xs font-mono">DEMO</button>
          <button onClick={exportDossier} disabled={!reconData} className="p-2 border border-slate-700 rounded-lg disabled:opacity-40" title="Export JSON"><Download className="w-4 h-4" /></button>
        </div>
      </header>

      <div className="px-6 py-2 bg-amber-950/40 border-b border-amber-900/50 text-[10px] font-mono text-amber-200 flex items-center gap-2">
        <ShieldCheck className="w-4 h-4" /> Use only against assets you are authorized to assess. DEMO findings are synthetic and not evidence of vulnerabilities.
      </div>

      {errorMessage && <div className="mx-4 mt-3 px-3 py-2 bg-red-950/60 border border-red-800 rounded-lg text-xs text-red-200">{errorMessage}</div>}
      {notice && <div className="mx-4 mt-3 px-3 py-2 bg-cyan-950/60 border border-cyan-800 rounded-lg text-xs text-cyan-200">{notice}</div>}

      <main className="flex-1 relative">
        <ReactFlow nodes={nodes} edges={edges} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onNodeClick={(event, node) => setSelectedItem(node.data)} nodeTypes={nodeTypes} fitView minZoom={0.25} maxZoom={1.8}>
          <Background gap={22} size={1} color="#172033" />
          <MiniMap pannable zoomable />
          <Controls />
        </ReactFlow>

        {reconData && (
          <div className="absolute left-4 top-4 w-72 bg-[#08101f]/95 border border-slate-800 rounded-xl p-4 shadow-2xl space-y-3">
            <div className="flex items-center justify-between"><span className="text-[10px] font-mono text-slate-500">SCAN STATUS</span><span className="text-[10px] font-mono text-amber-300">{reconData.metadata?.findings_mode}</span></div>
            <div className="grid grid-cols-3 gap-2 text-center"><div className="bg-slate-900 rounded p-2"><div className="text-lg font-bold">{reconData.subdomains?.length || 0}</div><div className="text-[9px] text-slate-500">ASSETS</div></div><div className="bg-slate-900 rounded p-2"><div className="text-lg font-bold">{reconData.services?.length || 0}</div><div className="text-[9px] text-slate-500">SERVICES</div></div><div className="bg-slate-900 rounded p-2"><div className="text-lg font-bold">{reconData.vulnerability_summary?.total || 0}</div><div className="text-[9px] text-slate-500">CVEs</div></div></div>
            <div className="text-[10px] text-slate-400">Source status: {reconData.metadata?.crt_sh_status}</div>
            <div className="text-[10px] text-slate-400">Network intelligence: {reconData.metadata?.network_intel_status}</div>
          </div>
        )}

        {selectedItem && (
          <aside className="absolute right-4 top-4 bottom-4 w-[380px] bg-[#08101f]/98 border border-slate-800 rounded-xl shadow-2xl overflow-hidden flex flex-col">
            <div className="p-4 border-b border-slate-800 flex justify-between items-center"><div className="font-mono text-xs text-cyan-300">ASSET INSPECTOR</div><button onClick={() => setSelectedItem(null)}><X className="w-4 h-4" /></button></div>
            <div className="p-4 overflow-y-auto space-y-4">
              <div><div className="text-[10px] text-slate-500">IDENTIFIER</div><div className="font-mono text-sm text-white break-all">{selectedItem.label || selectedItem.serviceName || `${selectedItem.port}`}</div></div>
              {selectedItem.vulnerabilities?.length > 0 && <div className="space-y-2"><div className="text-[10px] text-slate-500">CORRELATIONS</div>{selectedItem.vulnerabilities.map((v) => <div key={v.cve_id} className="bg-red-950/30 border border-red-900/60 rounded-lg p-3 space-y-2"><div className="flex justify-between"><span className="font-mono font-bold text-red-300">{v.cve_id}</span><span className="text-[10px] text-amber-300">{v.severity} · {v.cvss_score}</span></div><p className="text-xs text-slate-300">{v.description}</p><p className="text-[10px] text-slate-500">Confidence: {v.confidence || 'unknown'} · Source: {v.source || 'unknown'}</p><div className="text-[10px] text-cyan-300">Remediation: {v.remediation}</div><a className="inline-flex items-center gap-1 text-[10px] text-cyan-400" href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cve_id)}`} target="_blank" rel="noreferrer">Open NVD <ExternalLink className="w-3 h-3" /></a></div>)}</div>}
              {selectedItem.banner && <div><div className="text-[10px] text-slate-500">BANNER</div><pre className="mt-1 p-3 bg-slate-950 rounded-lg text-[10px] text-emerald-300 whitespace-pre-wrap break-all">{selectedItem.banner}</pre></div>}
            </div>
            <div className="mt-auto p-3 border-t border-slate-800 text-[9px] text-slate-500 font-mono">Findings require independent validation before remediation.</div>
          </aside>
        )}
      </main>
    </div>
  );
}

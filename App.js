import { useState, useRef, useEffect } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";

//Placeholder for dashboard
const vulnData = [
  { month: "Jan", count: 16 }, { month: "Feb", count: 13 },
  { month: "Mar", count: 20 }, { month: "Apr", count: 18 }, { month: "May", count: 23 },
];
const activityItems = [
  { label: "3 new scans processed",        tag: "Scan",     color: "#2563eb", bg: "#eff6ff" },
  { label: "5 tickets created",            tag: "Ticket",   color: "#7c3aed", bg: "#f5f3ff" },
  { label: "2 tickets closed",             tag: "Resolved", color: "#16a34a", bg: "#f0fdf4" },
  { label: "Critical vuln in API Gateway", tag: "Critical", color: "#dc2626", bg: "#fef2f2" },
];

//Placeholder cve details
const cveDetails = {
  "CVE-2024-3094": {
    cvss: 9.8, confidence: 92, severity: "Critical",
    title: "XZ Utils backdoor (liblzma)",
    why: "A malicious backdoor was introduced into upstream liblzma allowing remote code execution via SSH on affected distributions. Exposed servers can be fully compromised.",
    fixes: ["Downgrade xz-utils to version 5.4.6 or earlier", "Restart sshd on affected hosts", "Audit authorized_keys for unknown entries"] },
  "CVE-2026-33845": {
    cvss: 9.6, confidence: 88, severity: "Critical",
    title: "OpenSSL heap overflow in X.509 parser",
    why: "OpenSSL heap overflow in X.509 parser allows remote code execution via crafted certificate chains sent during TLS handshake.",
    fixes: ["Update OpenSSL to 3.3.1 or later", "Restart all services using OpenSSL", "Rotate TLS certificates on affected hosts"] },
  "CVE-2026-44012": {
    cvss: 9.1, confidence: 95, severity: "Critical",
    title: "Redis Lua sandbox escape",
    why: "Redis Lua sandbox escape allows authenticated users to run arbitrary OS commands via crafted Lua scripts, bypassing access controls.",
    fixes: ["Upgrade Redis to 7.2.5 or later", "Disable Lua scripting if not required", "Restrict Redis network access to trusted IPs"] },
  "CVE-2026-33846": {
    cvss: 8.2, confidence: 81, severity: "High",
    title: "Kubernetes kubelet path traversal",
    why: "A path traversal vulnerability in the Kubernetes kubelet API allows attackers with network access to read arbitrary files from the host filesystem, potentially exposing secrets and credentials.",
    fixes: ["Upgrade Kubernetes to 1.29.4 or later", "Restrict kubelet API access via network policy", "Rotate all secrets stored on affected nodes"] },
  "CVE-2026-12012": {
    cvss: 6.3, confidence: 77, severity: "Medium",
    title: "nginx HTTP/3 use-after-free",
    why: "A use-after-free bug in nginx's HTTP/3 QUIC implementation can be triggered by a malformed QUIC packet, potentially leading to denial of service or limited memory disclosure.",
    fixes: ["Upgrade nginx to 1.27.3 or later", "Disable HTTP/3 support if not required", "Apply vendor patch NGINX-2026-001"] } 
};

//placeholder vulnerabilities
const allRisks = Object.entries(cveDetails).map(([id, d]) => ({ id, cvss: d.cvss, severity: d.severity, title: d.title }));
const vulnRows = [
  { id: "CVE-2024-3094",  title: "",                                  severity: "Critical", cvss: 9.8, asset: "db-analytics-02"  },
  { id: "CVE-2026-33845", title: "OpenSSL heap overflow in X.509 parser", severity: "Critical", cvss: 9.6, asset: "edge-gw-prod-01"  },
  { id: "CVE-2026-44012", title: "Redis Lua sandbox escape",           severity: "Critical", cvss: 9.1, asset: "cache-shard-7"    },
  { id: "CVE-2026-33846", title: "Kubernetes kubelet path traversal",  severity: "High",     cvss: 8.2, asset: "k8s-cluster-eu"  },
  { id: "CVE-2026-12012", title: "nginx HTTP/3 use-after-free",        severity: "Medium",   cvss: 6.3, asset: "edge-gw-prod-02" },
];
const validationRows = [
  { id: "CVE-2024-3094",  severity: "Critical", status: "Validated",    desc: "OpenSSL heap overflow in X.509 parser"  },
  { id: "CVE-2026-33845", severity: "Critical", status: "Needs Review", desc: "Kubernetes kubelet path traversal"      },
  { id: "CVE-2026-44012", severity: "Critical", status: "Validated",    desc: "Redis Lua sandbox escape"               },
  { id: "CVE-2026-33846", severity: "High",     status: "Validated",    desc: "Kubernetes kubelet path traversal"      },
  { id: "CVE-2026-12012", severity: "Medium",   status: "Needs Review", desc: "nginx HTTP/3 use-after-free"            },
];

//styling
const css = `
  @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&display=swap');
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { height: 100%; }
  body {
    font-family: 'DM Sans', sans-serif;
    background: #f0f2f7;
    height: 100%; padding: 24px;
    display: flex; flex-direction: column;
  }
  #root { flex: 1; display: flex; flex-direction: column; }

  /* shell */
  .shell { width: 100%; padding: 16px; flex: 1; display: flex; flex-direction: column; min-height: 0; }

  /* nav */
  .nav { display:flex; justify-content:space-between; align-items:center; margin-bottom:20px; padding:0 4px; flex-wrap:wrap; gap:8px; flex-shrink:0; }
  .nav-links { display:flex; gap:4px; flex-wrap:wrap; }
  .nav-btn { display:flex; align-items:center; gap:6px; padding:8px 16px; border-radius:20px; border:none; background:transparent; font-family:'DM Sans',sans-serif; font-size:14px; font-weight:500; color:#666; cursor:pointer; transition:all .2s; white-space:nowrap; }
  .nav-btn:hover { background:rgba(0,0,0,.05); color:#333; }
  .nav-btn.active { background:#2563eb; color:#fff; }
  .avatar { width:34px; height:34px; border-radius:50%; background:#d1d5db; display:flex; align-items:center; justify-content:center; color:#6b7280; cursor:pointer; flex-shrink:0; }

  /* stepper */
  .stepper { display:grid; grid-template-columns:repeat(11, 1fr); align-items:flex-start; margin-bottom:24px; flex-shrink:0; width:100%; }
  .step { display:flex; flex-direction:column; align-items:center; position:relative; }
  .step-connector { height:2px; margin-top:19px; width:100%; }
  .step-circle { width:40px; height:40px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:18px; flex-shrink:0; border:2px solid transparent; }
  .step-circle.done { background:#22c55e; border-color:#22c55e; color:#fff; }
  .step-circle.active { background:#2563eb; border-color:#2563eb; color:#fff; }
  .step-circle.pending { background:#e5e7eb; border-color:#e5e7eb; color:#9ca3af; }
  .step-label { font-size:11px; font-weight:500; color:#6b7280; margin-top:6px; white-space:nowrap; }
  .step-label.active { color:#2563eb; font-weight:600; }
  .step-label.done { color:#22c55e; }

  /* page card */
  .page-card { background:#fff; border-radius:16px; padding:24px; box-shadow:0 1px 4px rgba(0,0,0,.06); display:flex; flex-direction:column; overflow:auto; }
  .page-title { font-size:18px; font-weight:700; color:#111; margin-bottom:4px; }
  .page-sub { font-size:13px; color:#6b7280; margin-bottom:20px; }

  /* footer */
  .page-footer { display:flex; justify-content:space-between; align-items:center; margin-top:16px; flex-shrink:0; }
  .step-counter { font-size:13px; color:#9ca3af; position:absolute; left:50%; transform:translateX(-50%); }
  .btn { padding:9px 24px; border-radius:20px; border:none; font-family:'DM Sans',sans-serif; font-size:14px; font-weight:600; cursor:pointer; transition:all .2s; }
  .btn-ghost { background:#e5e7eb; color:#374151; }
  .btn-ghost:hover { background:#d1d5db; }
  .btn-primary { background:#2563eb; color:#fff; }
  .btn-primary:hover { background:#1d4ed8; }

  /* upload */
  .dropzone { border:2px dashed #d1d5db; border-radius:12px; flex:1; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:12px; cursor:pointer; transition:all .2s; min-height:180px; }
  .dropzone:hover, .dropzone.over { border-color:#2563eb; background:#eff6ff; }
  .dropzone-icon { color:#9ca3af; }
  .dropzone-main { font-size:14px; color:#374151; font-weight:500; }
  .dropzone-sub { font-size:12px; color:#9ca3af; }
  .uploaded-file { display:flex; align-items:center; gap:10px; padding:12px 16px; background:#f9fafb; border-radius:10px; border:1px solid #e5e7eb; }
  .uploaded-name { font-size:13px; font-weight:500; color:#374151; }
  .uploaded-size { font-size:12px; color:#9ca3af; }

  /* ai analysis */
  .ai-stats { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-bottom:16px; }
  .ai-stat { background:#f9fafb; border-radius:12px; padding:16px 20px; }
  .ai-stat-label { font-size:12px; color:#6b7280; font-weight:500; margin-bottom:8px; }
  .ai-stat-val { font-size:28px; font-weight:500; color:#111; }
  .ai-stat-val.orange { color:#f97316; }
  .top-risks { background:#f9fafb; border-radius:12px; padding:16px 20px; margin-bottom:16px; }
  .top-risks-title { font-size:13px; font-weight:600; color:#374151; margin-bottom:10px; }
  .risk-row { font-size:13px; color:#374151; padding:6px 0; border-bottom:1px solid #e5e7eb; cursor:pointer; transition:color .15s; }
  .risk-row:last-child { border-bottom:none; }
  .risk-row:hover { color:#2563eb; }
  td.cve-link { color:#2563eb; font-size:13px; cursor:pointer; }
  td.cve-link:hover { text-decoration:underline; color:#1d4ed8; }
  .ai-insight-box { background:#f5f3ff; border-radius:12px; padding:20px; }
  .ai-insight-header { display:flex; align-items:center; gap:8px; margin-bottom:8px; }
  .ai-insight-title { font-size:14px; font-weight:700; color:#7c3aed; }
  .ai-insight-analyzing { font-size:13px; color:#7c3aed; margin-bottom:16px; font-style:italic; }
  .ai-insight-chips { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
  .ai-chip { }
  .ai-chip-val { font-size:14px; font-weight:700; color:#7c3aed; }
  .ai-chip-desc { font-size:12px; color:#9ca3af; }

  /* cve detail */
  .cve-scores { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:16px; }
  .cve-score-card { background:#f9fafb; border-radius:12px; padding:16px 20px; }
  .cve-score-label { font-size:12px; color:#6b7280; font-weight:500; margin-bottom:8px; }
  .cve-score-val { font-size:36px; font-weight:500; }
  .cve-score-sub { font-size:12px; color:#9ca3af; margin-top:4px; }
  .cve-section { background:#f9fafb; border-radius:12px; padding:16px 20px; margin-bottom:12px; }
  .cve-section-title { font-size:13px; font-weight:600; color:#374151; margin-bottom:8px; }
  .cve-section-text { font-size:13px; color:#6b7280; line-height:1.6; }
  .cve-fix-list { list-style:none; display:flex; flex-direction:column; gap:6px; }
  .cve-fix-item { font-size:13px; color:#6b7280; display:flex; gap:8px; }
  .cve-fix-num { font-weight:700; color:#374151; flex-shrink:0; }
  .back-link { display:flex; align-items:center; gap:4px; font-size:13px; color:#2563eb; cursor:pointer; margin-bottom:16px; font-weight:500; }
  .back-link:hover { color:#1d4ed8; }

  /* select */
  .vuln-table { width:100%; border-collapse:collapse; }
  .vuln-table th { font-size:12px; font-weight:600; color:#9ca3af; text-align:left; padding:8px 12px; border-bottom:1px solid #e5e7eb; }
  .vuln-table td { font-size:13px; color:#374151; padding:10px 12px; border-bottom:1px solid #f3f4f6; }
  .vuln-table tr.selected td { background:#eff6ff; }
  .vuln-table tr:hover td { background:#f9fafb; cursor:pointer; }
  .vuln-table tr.selected:hover td { background:#dbeafe; }
  .severity-pill { display:inline-block; padding:3px 10px; border-radius:20px; font-size:12px; font-weight:600; }
  .sev-critical { background:#fee2e2; color:#dc2626; }
  .sev-high { background:#ffedd5; color:#ea580c; }
  .sev-medium { background:#fef9c3; color:#ca8a04; }
  .cb { width:16px; height:16px; border-radius:4px; border:2px solid #d1d5db; appearance:none; -webkit-appearance:none; cursor:pointer; flex-shrink:0; }
  .cb:checked { background:#2563eb; border-color:#2563eb; background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 10 8' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M1 4l2.5 2.5L9 1' stroke='white' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E"); background-repeat:no-repeat; background-position:center; background-size:10px; }

  /* validation */
  .val-header { display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:6px; }
  .val-issues-label { font-size:12px; color:#6b7280; font-weight:500; }
  .val-issues-count { font-size:40px; font-weight:500; color:#f97316; }
  .val-desc { font-size:13px; color:#6b7280; margin-bottom:20px; line-height:1.5; }
  .val-row { background:#f9fafb; border-radius:12px; padding:16px 20px; margin-bottom:10px; }
  .val-row-top { display:flex; align-items:center; gap:8px; margin-bottom:6px; flex-wrap:wrap; }
  .val-cve { font-size:13px; font-weight:700; color:#111; }
  .val-status { display:flex; align-items:center; gap:4px; padding:3px 10px; border-radius:20px; font-size:12px; font-weight:600; }
  .val-validated { background:#dcfce7; color:#16a34a; }
  .val-review { background:#fef9c3; color:#ca8a04; }
  .val-sub { font-size:12px; color:#9ca3af; margin-bottom:12px; }
  .val-checks { display:flex; gap:20px; flex-wrap:wrap; }
  .val-check { display:flex; align-items:center; gap:6px; font-size:12px; color:#374151; }
  .check-icon { color:#22c55e; font-size:14px; }

  /* dashboard */
  .heading { margin-bottom:16px; padding:0 4px; flex-shrink:0; }
  .heading h1 { font-size:clamp(16px,2.5vw,22px); font-weight:700; color:#111; }
  .heading-sub { font-size:clamp(11px,1.4vw,13px); color:#6b7280; margin-top:2px; display:flex; align-items:center; gap:4px; cursor:pointer; }
  .stats-row { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:12px; flex-shrink:0; }
  .stat-card { background:#fff; border-radius:16px; padding:18px 20px; box-shadow:0 1px 4px rgba(0,0,0,.06); min-width:0; }
  .stat-label { font-size:clamp(11px,1.4vw,13px); color:#6b7280; font-weight:500; margin-bottom:10px; }
  .stat-value { font-size:clamp(22px,3.5vw,32px); font-weight:500; color:#111; display:flex; align-items:baseline; gap:6px; flex-wrap:wrap; }
  .stat-delta { font-size:clamp(11px,1.4vw,13px); font-weight:600; color:#ef4444; }
  .stat-value.critical { color:#ef4444; }
  .stat-value.medium { color:#f97316; }
  .mid-row { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:12px; flex:1; min-height:0; }
  .chart-card { background:#fff; border-radius:16px; padding:20px; box-shadow:0 1px 4px rgba(0,0,0,.06); min-width:0; display:flex; flex-direction:column; }
  .chart-title { font-size:clamp(12px,1.5vw,14px); font-weight:600; color:#374151; margin-bottom:16px; flex-shrink:0; }
  .chart-grow { flex:1; min-height:0; }
  .insight-card { background:#dbeafe; border-radius:16px; padding:20px 24px; display:flex; flex-direction:column; min-width:0; }
  .insight-label { font-size:clamp(11px,1.4vw,13px); font-weight:700; color:#1d4ed8; letter-spacing:.02em; align-self:flex-start; }
  .insight-text { font-size:clamp(13px,1.8vw,18px); font-weight:500; color:#1e40af; line-height:1.5; text-align:center; flex:1; display:flex; align-items:center; justify-content:center; }
  .activity-card { background:#fff; border-radius:16px; padding:18px 24px; box-shadow:0 1px 4px rgba(0,0,0,.06); flex-shrink:0; }
  .activity-title { font-size:clamp(12px,1.5vw,14px); font-weight:600; color:#374151; margin-bottom:14px; }
  .activity-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; }
  .activity-item { border-radius:12px; padding:14px 16px; display:flex; flex-direction:column; gap:8px; min-width:0; }
  .activity-tag { font-size:11px; font-weight:700; white-space:nowrap; }
  .activity-label { font-size:clamp(12px,1.3vw,13px); font-weight:500; color:#374151; line-height:1.4; }

  /* chat bubble */
  .chat-bubble { position:fixed; bottom:28px; right:28px; width:44px; height:44px; border-radius:50%; background:#7c3aed; display:flex; align-items:center; justify-content:center; color:white; cursor:pointer; box-shadow:0 4px 16px rgba(124,58,237,.45); font-size:20px; z-index:100; }

  @media (max-width:700px) {
    body { padding:12px; }
    .stats-row { grid-template-columns:repeat(2,1fr); }
    .mid-row { grid-template-columns:1fr; }
    .activity-grid { grid-template-columns:repeat(2,1fr); }
    .ai-stats { grid-template-columns:1fr 1fr; }
    .cve-scores { grid-template-columns:1fr; }
  }
`;

//step icons
const StepIcons = {
  "Upload Scan": (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
    </svg>
  ),
  "AI Summary": (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2 L13.5 10.5 L22 12 L13.5 13.5 L12 22 L10.5 13.5 L2 12 L10.5 10.5 Z"/>
    </svg>
  ),
  "Select": (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>
    </svg>
  ),
  "Validation": (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
    </svg>
  ),
  "Generate Ticket": (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="4 7 4 4 20 4 20 7"/><line x1="9" y1="20" x2="15" y2="20"/><line x1="12" y1="4" x2="12" y2="20"/>
    </svg>
  ),
  "Review & Send": (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
    </svg>
  ) };

const STEPS = ["Upload Scan", "AI Summary", "Select", "Validation", "Generate Ticket", "Review & Send"];

//Stepper component
function Stepper({ currentStep }) {
  return (
    <div className="stepper">
      {STEPS.map((label, i) => {
        const done = i < currentStep;
        const active = i === currentStep;
        return (
          <>
            <div key={label} className="step">
              <div className={`step-circle ${done ? "done" : active ? "active" : "pending"}`}>
                {done
                  ? <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                  : StepIcons[label]}
              </div>
              <div className={`step-label ${done ? "done" : active ? "active" : ""}`}>{label}</div>
            </div>
            {i < STEPS.length - 1 && (
              <div key={label+"-conn"} className="step-connector" style={{ background: done ? "#22c55e" : "#e5e7eb" }} />
            )}
          </>
        );
      })}
    </div>
  );
}

//nav bar
function Nav({ activeTab, setActiveTab }) {
  return (
    <nav className="nav">
      <div className="nav-links">
        {["dashboard", "upload-scan", "tickets"].map(tab => (
          <button key={tab} className={`nav-btn ${activeTab === tab ? "active" : ""}`} onClick={() => setActiveTab(tab)}>
            <span>✦</span>
            {tab === "dashboard" ? "Dashboard" : tab === "upload-scan" ? "Upload Scan" : "Tickets"}
          </button>
        ))}
      </div>
      <div className="avatar">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
        </svg>
      </div>
    </nav>
  );
}

//footer
function Footer({ step, onBack, onNext, nextLabel = "Next", disableNext = false }) {
  return (
    <div className="page-footer" style={{ position: "relative" }}>
      <button className="btn btn-ghost" onClick={onBack}>Back</button>
      <span className="step-counter">Step {step + 1} of {STEPS.length}</span>
      <button className="btn btn-primary" onClick={onNext} disabled={disableNext} style={{ opacity: disableNext ? 0.5 : 1 }}>
        {nextLabel}
      </button>
    </div>
  );
}

//Upload step 1: Upload Scan
function UploadStep({ onNext, onBack, file, setFile }) {
  const [over, setOver] = useState(false);

  const handleFile = f => { if (f) setFile(f); };

  return (
    <>
      <div className="page-card">
        <div className="page-title">Upload Scan</div>
        <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 12 }}>
          {!file ? (
            <div
              className={`dropzone ${over ? "over" : ""}`}
              onDragOver={e => { e.preventDefault(); setOver(true); }}
              onDragLeave={() => setOver(false)}
              onDrop={e => { e.preventDefault(); setOver(false); handleFile(e.dataTransfer.files[0]); }}
              onClick={() => document.getElementById("file-input").click()}
            >
              <input id="file-input" type="file" accept=".json" style={{ display: "none" }} onChange={e => handleFile(e.target.files[0])} />
              <svg className="dropzone-icon" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
              </svg>
              <div className="dropzone-main">Drag and drop your scan or click to browse files</div>
              <div className="dropzone-sub">Supports .json</div>
            </div>
          ) : (
            <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 12 }}>
              <div className="uploaded-file">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="20 6 9 17 4 12"/>
                </svg>
                <div>
                  <div className="uploaded-name">{file.name}</div>
                  <div className="uploaded-size">{(file.size / 1024).toFixed(1)} KB</div>
                </div>
                <button style={{ marginLeft: "auto", background: "none", border: "none", cursor: "pointer", color: "#9ca3af", fontSize: 18 }} onClick={() => setFile(null)}>×</button>
              </div>
            </div>
          )}
        </div>
      </div>
      <Footer step={0} onBack={onBack} onNext={onNext} disableNext={!file} />
    </>
  );
}

//Upload step 2: AI Summary
function AISummaryStep({ onNext, onBack, onCveClick }) {
  const [showAll, setShowAll] = useState(false);
  return (
    <>
      <div className="page-card">
        <div className="page-title">AI Analysis</div>
        <div className="page-sub">Analyze results with AI-powered insights</div>

        {(() => {
          const total = allRisks.length;
          const critical = allRisks.filter(r => r.severity === "Critical").length;
          const avgCvss = (allRisks.reduce((s, r) => s + r.cvss, 0) / total).toFixed(1);
          return (
            <div className="ai-stats">
              <div className="ai-stat">
                <div className="ai-stat-label">Total Vulnerabilities</div>
                <div className="ai-stat-val">{total}</div>
              </div>
              <div className="ai-stat">
                <div className="ai-stat-label">Critical Risk</div>
                <div className="ai-stat-val" style={{ color: "#dc2626" }}>{critical}</div>
              </div>
              <div className="ai-stat">
                <div className="ai-stat-label">Average CVSS</div>
                <div className="ai-stat-val orange">{avgCvss}</div>
              </div>
            </div>
          );
        })()}

        <div className="top-risks">
          <div className="top-risks-title">Risks</div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 120px 60px", gap: 8, padding: "0 0 6px 0", borderBottom: "1px solid #e5e7eb", marginBottom: 4 }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: "#9ca3af" }}>CVE</span>
            <span style={{ fontSize: 11, fontWeight: 600, color: "#9ca3af" }}>SEVERITY</span>
            <span style={{ fontSize: 11, fontWeight: 600, color: "#9ca3af", textAlign: "right" }}>CVSS</span>
          </div>
          {allRisks.slice(0, 3).map(r => (
            <div key={r.id} className="risk-row" style={{ display: "grid", gridTemplateColumns: "1fr 120px 60px", gap: 8, alignItems: "center" }} onClick={() => onCveClick(r.id)}>
              <span style={{ }}>{r.id}</span>
              <div><span className={`severity-pill sev-${r.severity.toLowerCase()}`}>{r.severity}</span></div>
              <span style={{ fontSize: 12, color: "#6b7280", textAlign: "right" }}>{r.cvss}</span>
            </div>
          ))}
          {showAll && allRisks.slice(3).map(r => (
            <div key={r.id} className="risk-row" style={{ display: "grid", gridTemplateColumns: "1fr 120px 60px", gap: 8, alignItems: "center" }} onClick={() => onCveClick(r.id)}>
              <span style={{ }}>{r.id}</span>
              <div><span className={`severity-pill sev-${r.severity.toLowerCase()}`}>{r.severity}</span></div>
              <span style={{ fontSize: 12, color: "#6b7280", textAlign: "right" }}>{r.cvss}</span>
            </div>
          ))}
          {allRisks.length > 3 && (
            <div style={{ paddingTop: 10, textAlign: "center" }}>
              <span
                style={{ fontSize: 13, color: "#2563eb", fontWeight: 600, cursor: "pointer", userSelect: "none" }}
                onClick={() => setShowAll(s => !s)}
                onMouseEnter={e => e.target.style.textDecoration = "underline"}
                onMouseLeave={e => e.target.style.textDecoration = "none"}
              >
                {showAll ? "▲ Hide" : `+ ${allRisks.length - 3} more`}
              </span>
            </div>
          )}
        </div>

        <div className="ai-insight-box">
          <div className="ai-insight-header">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#7c3aed" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>
            </svg>
            <div className="ai-insight-title">AI-Powered Analysis</div>
          </div>
          <div className="ai-insight-analyzing">Analyzing vulnerability patterns and severity prioritization...</div>
          <div className="ai-insight-chips">
            <div className="ai-chip">
              <div className="ai-chip-val">3 Critical Issues</div>
              <div className="ai-chip-desc">Require immediate attention</div>
            </div>
            <div className="ai-chip">
              <div className="ai-chip-val">5 False Positives</div>
              <div className="ai-chip-desc">AI-filtered for review</div>
            </div>
          </div>
        </div>
      </div>
      <Footer step={1} onBack={onBack} onNext={onNext} />
    </>
  );
}

//CVE Detail (sub-page of AI Summary/Select)
function CveDetailStep({ cveId, onBack, onNext, backLabel }) {
  const d = cveDetails[cveId];
  const cvssColor = d.cvss >= 9 ? "#dc2626" : d.cvss >= 7 ? "#f97316" : "#ca8a04";
  const confColor = d.confidence >= 90 ? "#22c55e" : "#f97316";
  return (
    <>
      <div className="page-card">
        <div className="back-link" onClick={onBack}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
          {backLabel || "Back to AI Summary"}
        </div>
        <div className="page-title">{cveId}</div>
        <div className="page-sub">Analyse results with AI-powered insights</div>

        <div className="cve-scores">
          <div className="cve-score-card">
            <div className="cve-score-label">CVSS Score</div>
            <div className="cve-score-val" style={{ color: cvssColor }}>{d.cvss}</div>
          </div>
          <div className="cve-score-card">
            <div className="cve-score-label">AI Confidence</div>
            <div className="cve-score-val" style={{ color: confColor }}>{d.confidence}%</div>
            <div className="cve-score-sub">Validated against NVD & vendor advisory</div>
          </div>
        </div>

        <div className="cve-section">
          <div className="cve-section-title">Why This Matters</div>
          <div className="cve-section-text">{d.why}</div>
        </div>

        <div className="cve-section">
          <div className="cve-section-title">Suggested Fix</div>
          <ol className="cve-fix-list">
            {d.fixes.map((f, i) => (
              <li key={i} className="cve-fix-item">
                <span className="cve-fix-num">{i + 1}.</span> {f}
              </li>
            ))}
          </ol>
        </div>
      </div>

    </>
  );
}

//upload step 3: Select
function SelectStep({ onNext, onBack, selected, setSelected, onCveClick }) {
  const allChecked = vulnRows.every(r => selected.includes(r.id));
  const toggle = id => setSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id]);
  const toggleAll = () => setSelected(allChecked ? [] : vulnRows.map(r => r.id));

  return (
    <>
      <div className="page-card">
        <div className="page-title">Select Vulnerabilities</div>
        <div className="page-sub">Choose which findings to push through validation & ticketing.</div>
        <div style={{ overflowX: "auto" }}>
          <table className="vuln-table">
            <thead>
              <tr>
                <th><input type="checkbox" className="cb" checked={allChecked} onChange={toggleAll} /></th>
                <th>CVE</th>
                <th>Title</th>
                <th>Severity</th>
                <th>CVSS</th>
                <th>Asset</th>
              </tr>
            </thead>
            <tbody>
              {vulnRows.map(row => (
                <tr key={row.id} className={selected.includes(row.id) ? "selected" : ""} onClick={() => toggle(row.id)}>
                  <td><input type="checkbox" className="cb" checked={selected.includes(row.id)} onChange={() => toggle(row.id)} onClick={e => e.stopPropagation()} /></td>
                  <td className="cve-link" onClick={e => { e.stopPropagation(); onCveClick(row.id); }}>{row.id}</td>
                  <td style={{ color: "#6b7280" }}>{row.title}</td>
                  <td>
                    <span className={`severity-pill sev-${row.severity.toLowerCase()}`}>{row.severity}</span>
                  </td>
                  <td style={{ }}>{row.cvss}</td>
                  <td style={{ color: "#6b7280", fontSize: 12 }}>{row.asset}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <Footer step={2} onBack={onBack} onNext={onNext} disableNext={selected.length === 0} />
    </>
  );
}

//Upload step 4: Validation
function ValidationStep({ onNext, onBack, selected, onCveClick }) {
  return (
    <>
      <div className="page-card">
        <div className="val-header">
          <div>
            <div className="page-title">Validation</div>
            <div style={{ fontSize: 12, color: "#9ca3af", marginBottom: 4 }}>Anti-hallucination</div>
          </div>
          <div style={{ textAlign: "right" }}>
            <div className="val-issues-label">Issues Found</div>
            <div className="val-issues-count">
              {validationRows.filter(r => selected.includes(r.id) && r.status === "Needs Review").length}
            </div>
          </div>
        </div>
        <div className="val-desc">For each selected vulnerability we cross-check the AI summary, remediation, severity classification, and flag any potential hallucinations against NVD, MITRE, and vendor advisories.</div>

        {validationRows.filter(row => selected.includes(row.id)).map(row => (
          <div key={row.id} className="val-row">
            <div className="val-row-top">
              <span className="val-cve" style={{ cursor: "pointer" }} onClick={() => onCveClick(row.id)}>{row.id}</span>
              <span className={`severity-pill sev-${row.severity.toLowerCase()}`}>{row.severity}</span>
              <span className={`val-status ${row.status === "Validated" ? "val-validated" : "val-review"}`}>
                {row.status === "Validated"
                  ? <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                  : <span style={{ fontSize: 14 }}>✋</span>}
                {row.status}
              </span>
            </div>
            <div className="val-sub">{row.desc}</div>
            <div className="val-checks">
              {["Summary", "Remediation", "Severity", "No hallucination"].map(c => (
                <div key={c} className="val-check">
                  <svg className="check-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                  {c}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
      <Footer step={3} onBack={onBack} onNext={onNext} />
    </>
  );
}

//Upload step 5: Generate Ticket (placeholder)
function GenerateTicketStep({ onNext, onBack }) {
  return (
    <>
      <div className="page-card" />
      <Footer step={4} onBack={onBack} onNext={onNext} nextLabel="Next" />
    </>
  );
}

//Upload step 6: Review & Send (placeholder)
function ReviewSendStep({ onNext, onBack }) {
  return (
    <>
      <div className="page-card" />
      <Footer step={5} onBack={onBack} onNext={onNext} nextLabel="Done" />
    </>
  );
}

//Dashboard
function Dashboard() {
  const chartWrapRef = useRef(null);
  const [chartHeight, setChartHeight] = useState(180);

  useEffect(() => {
    if (!chartWrapRef.current) return;
    const ro = new ResizeObserver(entries => {
      for (const e of entries) setChartHeight(e.contentRect.height);
    });
    ro.observe(chartWrapRef.current);
    return () => ro.disconnect();
  }, []);

  return (
    <>
      <div className="heading">
        <h1>Security Overview</h1>
        <div className="heading-sub">Last 7 days ▾</div>
      </div>
      <div className="stats-row">
        <div className="stat-card"><div className="stat-label">Total Vulnerabilities</div><div className="stat-value">47 <span className="stat-delta">+9%</span></div></div>
        <div className="stat-card"><div className="stat-label">Critical</div><div className="stat-value critical">8</div></div>
        <div className="stat-card"><div className="stat-label">Medium</div><div className="stat-value medium">13</div></div>
        <div className="stat-card"><div className="stat-label">New Today</div><div className="stat-value">6</div></div>
      </div>
      <div className="mid-row">
        <div className="chart-card">
          <div className="chart-title">Vulnerabilities over time</div>
          <div className="chart-grow" ref={chartWrapRef}>
            <ResponsiveContainer width="100%" height={chartHeight}>
              <BarChart data={vulnData} barSize={28}>
                <CartesianGrid vertical={false} stroke="#f3f4f6" />
                <XAxis dataKey="month" axisLine={false} tickLine={false} tick={{ fontSize: 12, fill: "#9ca3af" }} />
                <YAxis axisLine={false} tickLine={false} tick={{ fontSize: 11, fill: "#9ca3af" }} domain={[0, 30]} ticks={[0, 10, 20, 30]} />
                <Tooltip cursor={{ fill: "rgba(37,99,235,0.08)" }} contentStyle={{ borderRadius: 10, border: "none", boxShadow: "0 4px 20px rgba(0,0,0,.1)", fontSize: 13 }} />
                <Bar dataKey="count" fill="#2563eb" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="insight-card">
          <div className="insight-label">AI Insight</div>
          <div className="insight-text">Most critical issues affect external services. Consider prioritizing API Gateway and authentication layer patches.</div>
        </div>
      </div>
      <div className="activity-card">
        <div className="activity-title">Recent Activity</div>
        <div className="activity-grid">
          {activityItems.map((item, i) => (
            <div key={i} className="activity-item" style={{ background: item.bg }}>
              <span className="activity-tag" style={{ color: item.color }}>{item.tag}</span>
              <div className="activity-label">{item.label}</div>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

//Root
export default function App() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [uploadStep, setUploadStep] = useState(0);
  const [cveId, setCveId] = useState(null);
  const [selected, setSelected] = useState(vulnRows.map(r => r.id));
  const [prevStep, setPrevStep] = useState(1);
  const [uploadedFile, setUploadedFile] = useState(null);

  const goToTab = tab => { setActiveTab(tab); setUploadStep(0); setCveId(null); setUploadedFile(null); };

  const renderUploadContent = () => {
    if (cveId) {
      return <CveDetailStep cveId={cveId} onBack={() => setCveId(null)} onNext={() => { setCveId(null); }} backLabel={prevStep === 2 ? "Back to Select" : "Back to AI Summary"} />;
    }
    switch (uploadStep) {
      case 0: return <UploadStep onNext={() => setUploadStep(1)} onBack={() => goToTab("dashboard")} file={uploadedFile} setFile={setUploadedFile} />;
      case 1: return <AISummaryStep onNext={() => setUploadStep(2)} onBack={() => setUploadStep(0)} onCveClick={id => { setPrevStep(1); setCveId(id); }} />;
      case 2: return <SelectStep onNext={() => setUploadStep(3)} onBack={() => setUploadStep(1)} selected={selected} setSelected={setSelected} onCveClick={id => { setPrevStep(2); setCveId(id); }} />;
      case 3: return <ValidationStep onNext={() => setUploadStep(4)} onBack={() => setUploadStep(2)} selected={selected} onCveClick={id => { setPrevStep(3); setCveId(id); }} />;
      case 4: return <GenerateTicketStep onNext={() => setUploadStep(5)} onBack={() => setUploadStep(3)} />;
      case 5: return <ReviewSendStep onNext={() => goToTab("dashboard")} onBack={() => setUploadStep(4)} />;
      default: return null;
    }
  };

  return (
    <>
      <style>{css}</style>
      <div className="shell">
        <Nav activeTab={activeTab} setActiveTab={goToTab} />

        {activeTab === "upload-scan" && (
          <Stepper currentStep={cveId ? prevStep : uploadStep} />
        )}

        {activeTab === "dashboard" && <Dashboard />}
        {activeTab === "upload-scan" && renderUploadContent()}
        {activeTab === "tickets" && (
          <div className="page-card" style={{ alignItems: "center", justifyContent: "center", color: "#9ca3af", fontSize: 15 }}>
            Tickets page coming soon
          </div>
        )}

        <div className="chat-bubble">💬</div>
      </div>
    </>
  );
}

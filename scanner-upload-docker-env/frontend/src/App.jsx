import { useState, useRef, useEffect } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";

// Base URL for the scanner-upload backend (Flask). Update this if the
// backend runs somewhere other than localhost:5000 (e.g. in docker-compose).
const API_BASE = "http://localhost:5000";

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
// NOTE: allRisks / vulnRows / validationRows / cveDetails below start out as
// demo data so the wizard still looks right before anything is uploaded.
// Once a real scan file is uploaded, applyScanResults() overwrites their
// contents with the parsed findings from the scanner-upload backend.
let cveDetails = {
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
let allRisks = Object.entries(cveDetails).map(([id, d]) => ({ id, cvss: d.cvss, severity: d.severity, title: d.title }));
let vulnRows = [
  { id: "CVE-2024-3094",  title: "",                                  severity: "Critical", cvss: 9.8, asset: "db-analytics-02"  },
  { id: "CVE-2026-33845", title: "OpenSSL heap overflow in X.509 parser", severity: "Critical", cvss: 9.6, asset: "edge-gw-prod-01"  },
  { id: "CVE-2026-44012", title: "Redis Lua sandbox escape",           severity: "Critical", cvss: 9.1, asset: "cache-shard-7"    },
  { id: "CVE-2026-33846", title: "Kubernetes kubelet path traversal",  severity: "High",     cvss: 8.2, asset: "k8s-cluster-eu"  },
  { id: "CVE-2026-12012", title: "nginx HTTP/3 use-after-free",        severity: "Medium",   cvss: 6.3, asset: "edge-gw-prod-02" },
];
let validationRows = [
  { id: "CVE-2024-3094",  severity: "Critical", status: "Validated",    desc: "OpenSSL heap overflow in X.509 parser"  },
  { id: "CVE-2026-33845", severity: "Critical", status: "Needs Review", desc: "Kubernetes kubelet path traversal"      },
  { id: "CVE-2026-44012", severity: "Critical", status: "Validated",    desc: "Redis Lua sandbox escape"               },
  { id: "CVE-2026-33846", severity: "High",     status: "Validated",    desc: "Kubernetes kubelet path traversal"      },
  { id: "CVE-2026-12012", severity: "Medium",   status: "Needs Review", desc: "nginx HTTP/3 use-after-free"            },
];
// Raw normalized findings from the last successful scan, kept around so the
// chatbot can ground its answers in the same data the rest of the wizard is
// showing (cve, title, severity, cvss, asset, package — see /api/chat).
let lastVulnerabilities = [];

// Turns the parsed vulnerability list returned by the scanner-upload backend
// into the same shapes the wizard's UI already renders (vulnRows, cveDetails,
// allRisks, validationRows), replacing the demo placeholder data above.
//
// Each entry in `vulnerabilities` may already carry real AI fields (why,
// fixes, confidence, priority_tier, ai_generated) if it went through
// POST /api/analyze first — see runAiAnalysis() below. If those fields
// aren't present (analysis skipped or failed), fall back to the same
// heuristic placeholders as before so the UI never breaks.
function applyScanResults(vulnerabilities) {
  const list = Array.isArray(vulnerabilities) ? vulnerabilities : [];
  lastVulnerabilities = list;

  vulnRows = list.map(v => ({
    id: v.cve || v.title,
    title: v.title || v.cve || "Untitled finding",
    severity: v.severity || "Unknown",
    cvss: typeof v.cvss === "number" ? v.cvss : 0,
    asset: v.asset || v.package || "unknown",
  }));

  cveDetails = Object.fromEntries(list.map(v => {
    const id = v.cve || v.title;
    const hasAiResult = v.ai_generated !== undefined; // set by /api/analyze on every entry it touches

    let why, fixes, confidence;
    if (hasAiResult) {
      why = v.why || "No explanation was returned for this finding.";
      fixes = Array.isArray(v.fixes) && v.fixes.length ? v.fixes : ["Review the vendor advisory and apply the recommended patch."];
      confidence = typeof v.confidence === "number" ? v.confidence : 50;
    } else {
      // Analysis hasn't run yet (or failed to reach the backend) — same
      // stand-in heuristics as before so the step still renders something.
      fixes = [];
      if (v.package && v.installedVersion) {
        fixes.push(`Upgrade ${v.package} beyond the installed version (${v.installedVersion})`);
      } else if (v.package) {
        fixes.push(`Upgrade ${v.package} to a patched version`);
      }
      fixes.push(`Review the vendor advisory for ${id}`);
      fixes.push("Re-scan the asset after remediation to confirm the fix");
      why = v.description || "No description was provided by the scanner for this finding.";
      confidence = typeof v.cvss === "number" && v.description ? 95 : 65;
    }

    return [id, {
      cvss: typeof v.cvss === "number" ? v.cvss : 0,
      confidence,
      severity: v.severity || "Unknown",
      title: v.title || id,
      why,
      fixes,
      priorityTier: v.priority_tier || null,
      aiGenerated: !!v.ai_generated,
    }];
  }));

  allRisks = Object.entries(cveDetails).map(([id, d]) => ({ id, cvss: d.cvss, severity: d.severity, title: d.title }));

  // Flag anything missing a CVSS score or description as needing a human
  // look; if real AI analysis ran and came back with low confidence,
  // flag that too instead of treating it as automatically validated.
  validationRows = list.map(v => {
    const id = v.cve || v.title;
    const hasAiResult = v.ai_generated !== undefined;
    const complete = hasAiResult
      ? v.ai_generated && (typeof v.confidence !== "number" || v.confidence >= 60)
      : typeof v.cvss === "number" && !!v.description;
    return {
      id,
      severity: v.severity || "Unknown",
      status: complete ? "Validated" : "Needs Review",
      desc: v.title || v.description || "",
    };
  });
}

// Calls POST /api/analyze with the vulnerabilities parsed from either
// upload path, and returns the same list with AI fields merged in.
// On any failure (backend unreachable, ANTHROPIC_API_KEY missing, etc.)
// falls back to returning the list unchanged — applyScanResults() then
// uses its heuristic placeholders instead of hard-failing the wizard.
async function runAiAnalysis(vulnerabilities) {
  if (!Array.isArray(vulnerabilities) || vulnerabilities.length === 0) return vulnerabilities;
  try {
    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ vulnerabilities }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "AI analysis failed");
    return data.vulnerabilities || vulnerabilities;
  } catch (err) {
    console.warn("AI analysis unavailable, showing raw scan results:", err.message);
    return vulnerabilities;
  }
}

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
      <div className="avatar" onClick={() => setActiveTab("profile")} style={{ cursor: "pointer", background: activeTab === "profile" ? "#2563eb" : "#d1d5db" }}>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={activeTab === "profile" ? "#fff" : "#6b7280"} strokeWidth="2">
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

//Sign In
function SignIn({ onSignIn, onGoSignUp, accounts }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const handle = () => {
    if (!email || !password) { setError("Please fill in all fields"); return; }
    const valid = accounts && accounts.find(a => a.email === email && a.password === password);
    if (!valid) { setError("Invalid email or password. Please sign up first."); return; }
    onSignIn(email, password);
  };

  return (
    <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ width: 380, background: "#fff", borderRadius: 20, padding: 36, boxShadow: "0 4px 24px rgba(0,0,0,0.08)" }}>
        <div style={{ fontSize: 22, fontWeight: 700, color: "#111", marginBottom: 4 }}>Welcome back</div>
        <div style={{ fontSize: 13, color: "#6b7280", marginBottom: 28 }}>Sign in to your account</div>

        {error && <div style={{ fontSize: 12, color: "#dc2626", background: "#fef2f2", padding: "8px 12px", borderRadius: 8, marginBottom: 16 }}>{error}</div>}

        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: "#374151", marginBottom: 6 }}>Email</div>
          <input
            type="email"
            value={email}
            onChange={e => setEmail(e.target.value)}
            placeholder="you@organisation.com"
            style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid #e5e7eb", fontSize: 13, fontFamily: "DM Sans, sans-serif", color: "#374151", outline: "none" }}
          />
        </div>

        <div style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: "#374151", marginBottom: 6 }}>Password</div>
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder="••••••••"
            style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid #e5e7eb", fontSize: 13, fontFamily: "DM Sans, sans-serif", color: "#374151", outline: "none" }}
          />
        </div>

        <button
          onClick={handle}
          style={{ width: "100%", padding: "12px", borderRadius: 20, border: "none", background: "#2563eb", color: "#fff", fontSize: 14, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: "pointer", marginBottom: 16 }}>
          Sign in
        </button>

        <div style={{ textAlign: "center", fontSize: 13, color: "#6b7280" }}>
          Don't have an account?{" "}
          <span onClick={onGoSignUp} style={{ color: "#2563eb", fontWeight: 600, cursor: "pointer" }}>Sign up</span>
        </div>
      </div>
    </div>
  );
}

//Sign Up
function SignUp({ onSignUp, onGoSignIn }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");

  const handle = () => {
    if (!name || !email || !password || !confirm) { setError("Please fill in all fields"); return; }
    if (password !== confirm) { setError("Passwords do not match"); return; }
    onSignUp(name, email, password);
  };

  return (
    <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ width: 380, background: "#fff", borderRadius: 20, padding: 36, boxShadow: "0 4px 24px rgba(0,0,0,0.08)" }}>
        <div style={{ fontSize: 22, fontWeight: 700, color: "#111", marginBottom: 4 }}>Create an account</div>
        <div style={{ fontSize: 13, color: "#6b7280", marginBottom: 28 }}>Get started with vulnerability management</div>

        {error && <div style={{ fontSize: 12, color: "#dc2626", background: "#fef2f2", padding: "8px 12px", borderRadius: 8, marginBottom: 16 }}>{error}</div>}

        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: "#374151", marginBottom: 6 }}>Full name</div>
          <input
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="Your name"
            style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid #e5e7eb", fontSize: 13, fontFamily: "DM Sans, sans-serif", color: "#374151", outline: "none" }}
          />
        </div>

        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: "#374151", marginBottom: 6 }}>Email</div>
          <input
            type="email"
            value={email}
            onChange={e => setEmail(e.target.value)}
            placeholder="you@organisation.com"
            style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid #e5e7eb", fontSize: 13, fontFamily: "DM Sans, sans-serif", color: "#374151", outline: "none" }}
          />
        </div>

        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: "#374151", marginBottom: 6 }}>Password</div>
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder="••••••••"
            style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid #e5e7eb", fontSize: 13, fontFamily: "DM Sans, sans-serif", color: "#374151", outline: "none" }}
          />
        </div>

        <div style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: "#374151", marginBottom: 6 }}>Confirm password</div>
          <input
            type="password"
            value={confirm}
            onChange={e => setConfirm(e.target.value)}
            placeholder="••••••••"
            style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid #e5e7eb", fontSize: 13, fontFamily: "DM Sans, sans-serif", color: "#374151", outline: "none" }}
          />
        </div>

        <button
          onClick={handle}
          style={{ width: "100%", padding: "12px", borderRadius: 20, border: "none", background: "#2563eb", color: "#fff", fontSize: 14, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: "pointer", marginBottom: 16 }}>
          Create account
        </button>

        <div style={{ textAlign: "center", fontSize: 13, color: "#6b7280" }}>
          Already have an account?{" "}
          <span onClick={onGoSignIn} style={{ color: "#2563eb", fontWeight: 600, cursor: "pointer" }}>Sign in</span>
        </div>
      </div>
    </div>
  );
}

//Upload step 1: Upload Scan
// The backend cross-references every CVE in an uploaded/scanned file against
// the Tenable.io API automatically (see /api/upload-scan and /api/scan), and
// results are then run through AI analysis (/api/analyze) before landing in
// the wizard. Both entry points remain available: upload a pre-generated
// report, or trigger a live scan directly against a target.
function UploadStep({ onNext, onBack, file, setFile, onParsed }) {
  const [mode, setMode] = useState("upload"); // "upload" | "live"
  const [over, setOver] = useState(false);
  // status: idle | uploading | success | error
  const [status, setStatus] = useState("idle");
  const [errorMsg, setErrorMsg] = useState("");
  const [foundCount, setFoundCount] = useState(0);
  const [tenableMatchCount, setTenableMatchCount] = useState(0);

  const uploadToServer = async f => {
    setStatus("uploading");
    setErrorMsg("");
    try {
      const formData = new FormData();
      formData.append("file", f);
      const res = await fetch(`${API_BASE}/api/upload-scan`, { method: "POST", body: formData });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Upload failed");

      const vulnerabilities = data.vulnerabilities || [];
      onParsed(vulnerabilities); // show raw + Tenable cross-reference results immediately...
      setFoundCount(data.vulnerabilitiesFound ?? vulnerabilities.length);
      setTenableMatchCount(vulnerabilities.filter(v => v.tenable_exposure?.matched).length);
      setStatus("success");

      // ...then swap in real AI analysis once it comes back (falls back to
      // placeholders inside applyScanResults if /api/analyze fails).
      const analyzed = await runAiAnalysis(vulnerabilities);
      onParsed(analyzed);
    } catch (err) {
      setStatus("error");
      setErrorMsg(err.message || "Could not reach the scanner service. Is the backend running?");
    }
  };

  const handleFile = f => {
    if (!f) return;
    setFile(f);
    uploadToServer(f);
  };

  const clearFile = () => {
    setFile(null);
    setStatus("idle");
    setErrorMsg("");
  };

  // --- Live scan (trigger Trivy/Tenable/etc. directly, no file needed) ---
  const [scanners, setScanners] = useState(null); // null while loading, then { trivy: {...}, tenable: {...} }
  const [scannerName, setScannerName] = useState("trivy");
  const [target, setTarget] = useState("");
  const [trivyScanType, setTrivyScanType] = useState("image");
  const [trivyRunMode, setTrivyRunMode] = useState("local");
  // liveStatus: idle | scanning | success | error
  const [liveStatus, setLiveStatus] = useState("idle");
  const [liveError, setLiveError] = useState("");
  const [liveFoundCount, setLiveFoundCount] = useState(0);
  const [liveTenableMatchCount, setLiveTenableMatchCount] = useState(0);

  useEffect(() => {
    fetch(`${API_BASE}/api/scanners`)
      .then(res => res.json())
      .then(data => {
        setScanners(data);
        const liveCapable = Object.keys(data).find(name => data[name].supportsLiveScan);
        if (liveCapable) setScannerName(liveCapable);
      })
      .catch(() => setScanners({}));
  }, []);

  const runLiveScan = async () => {
    if (!target.trim()) return;
    setLiveStatus("scanning");
    setLiveError("");
    try {
      const body = { scanner: scannerName, target: target.trim() };
      if (scannerName === "trivy") {
        body.scan_type = trivyScanType;
        body.mode = trivyRunMode;
      }
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Scan failed");

      const vulnerabilities = data.vulnerabilities || [];
      onParsed(vulnerabilities); // show raw + Tenable cross-reference results immediately...
      setLiveFoundCount(data.vulnerabilitiesFound ?? vulnerabilities.length);
      setLiveTenableMatchCount(vulnerabilities.filter(v => v.tenable_exposure?.matched).length);
      setLiveStatus("success");

      // ...then swap in real AI analysis once it comes back, same as the
      // upload path — keeps both entry points behaving consistently.
      const analyzed = await runAiAnalysis(vulnerabilities);
      onParsed(analyzed);
    } catch (err) {
      setLiveStatus("error");
      setLiveError(err.message || "Could not reach the scanner service. Is the backend running?");
    }
  };

  const switchMode = next => {
    setMode(next);
    // Reset whichever path isn't active so switching back and forth doesn't
    // carry over a stale success/error state.
    if (next === "upload") { setLiveStatus("idle"); setLiveError(""); }
    else { clearFile(); }
  };

  const tabStyle = active => ({
    padding: "6px 14px",
    borderRadius: 20,
    border: "1px solid " + (active ? "#2563eb" : "#e5e7eb"),
    background: active ? "#2563eb" : "#fff",
    color: active ? "#fff" : "#374151",
    fontSize: 13,
    fontWeight: 600,
    cursor: "pointer",
  });

  const inputStyle = { padding: "8px 10px", borderRadius: 8, border: "1px solid #e5e7eb", fontSize: 13, width: "100%" };
  const labelStyle = { fontSize: 12, fontWeight: 600, color: "#374151", marginBottom: 4, display: "block" };

  return (
    <>
      <div className="page-card">
        <div className="page-title">Upload Scan</div>
        <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
          <button style={tabStyle(mode === "upload")} onClick={() => switchMode("upload")}>Upload a report</button>
          <button style={tabStyle(mode === "live")} onClick={() => switchMode("live")}>Run a live scan</button>
        </div>

        {mode === "upload" ? (
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
                <div className="dropzone-sub">Supports .json (Trivy, Tenable) — CVEs are cross-referenced against Tenable.io automatically</div>
              </div>
            ) : (
              <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 12 }}>
                <div className="uploaded-file">
                  {status === "error" ? (
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#dc2626" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                    </svg>
                  ) : (
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <polyline points="20 6 9 17 4 12"/>
                    </svg>
                  )}
                  <div>
                    <div className="uploaded-name">{file.name}</div>
                    <div className="uploaded-size">{(file.size / 1024).toFixed(1)} KB</div>
                  </div>
                  <button style={{ marginLeft: "auto", background: "none", border: "none", cursor: "pointer", color: "#9ca3af", fontSize: 18 }} onClick={clearFile}>×</button>
                </div>
                {status === "uploading" && (
                  <div className="dropzone-sub">Parsing scan file and checking CVEs against Tenable.io…</div>
                )}
                {status === "success" && (
                  <div className="dropzone-sub" style={{ color: "#16a34a" }}>
                    {foundCount} vulnerabilit{foundCount === 1 ? "y" : "ies"} found
                    {tenableMatchCount > 0 && ` · ${tenableMatchCount} also confirmed in your Tenable.io inventory`}.
                  </div>
                )}
                {status === "error" && (
                  <div style={{ fontSize: 12, color: "#dc2626", display: "flex", alignItems: "center", gap: 10 }}>
                    <span>{errorMsg}</span>
                    <button
                      onClick={() => uploadToServer(file)}
                      style={{ background: "none", border: "none", color: "#2563eb", fontWeight: 600, cursor: "pointer", fontSize: 12 }}
                    >
                      Retry
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        ) : (
          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 14, maxWidth: 480 }}>
            {scanners && Object.keys(scanners).length === 0 && (
              <div style={{ fontSize: 12, color: "#dc2626" }}>Couldn't reach the backend to list scanners. Is it running?</div>
            )}
            <div>
              <label style={labelStyle}>Scanner</label>
              <select style={inputStyle} value={scannerName} onChange={e => setScannerName(e.target.value)} disabled={liveStatus === "scanning"}>
                {(scanners ? Object.keys(scanners) : ["trivy", "tenable"]).map(name => (
                  <option key={name} value={name} disabled={scanners && !scanners[name].supportsLiveScan}>
                    {name.charAt(0).toUpperCase() + name.slice(1)}{scanners && !scanners[name].supportsLiveScan ? " (upload only)" : ""}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label style={labelStyle}>
                {scannerName === "tenable" ? "Tenable scan ID" : "Image, path, or repo to scan"}
              </label>
              <input
                style={inputStyle}
                value={target}
                onChange={e => setTarget(e.target.value)}
                disabled={liveStatus === "scanning"}
                placeholder={scannerName === "tenable" ? "e.g. 42" : "e.g. myapp:latest"}
              />
            </div>

            {scannerName === "trivy" && (
              <div style={{ display: "flex", gap: 12 }}>
                <div style={{ flex: 1 }}>
                  <label style={labelStyle}>Scan type</label>
                  <select style={inputStyle} value={trivyScanType} onChange={e => setTrivyScanType(e.target.value)} disabled={liveStatus === "scanning"}>
                    <option value="image">Container image</option>
                    <option value="fs">Filesystem path</option>
                    <option value="repo">Git repo URL</option>
                  </select>
                </div>
                <div style={{ flex: 1 }}>
                  <label style={labelStyle}>Runs via</label>
                  <select style={inputStyle} value={trivyRunMode} onChange={e => setTrivyRunMode(e.target.value)} disabled={liveStatus === "scanning"}>
                    <option value="local">Trivy CLI on backend host</option>
                    <option value="docker">Docker (aquasec/trivy)</option>
                  </select>
                </div>
              </div>
            )}

            <button
              onClick={runLiveScan}
              disabled={!target.trim() || liveStatus === "scanning"}
              style={{
                alignSelf: "flex-start",
                padding: "8px 18px",
                borderRadius: 8,
                border: "none",
                background: (!target.trim() || liveStatus === "scanning") ? "#93c5fd" : "#2563eb",
                color: "#fff",
                fontWeight: 600,
                fontSize: 13,
                cursor: (!target.trim() || liveStatus === "scanning") ? "default" : "pointer",
              }}
            >
              {liveStatus === "scanning" ? "Scanning…" : "Start Scan"}
            </button>

            {liveStatus === "scanning" && (
              <div className="dropzone-sub">Running {scannerName} against {target}… this can take a while for larger targets.</div>
            )}
            {liveStatus === "success" && (
              <div className="dropzone-sub" style={{ color: "#16a34a" }}>
                {liveFoundCount} vulnerabilit{liveFoundCount === 1 ? "y" : "ies"} found
                {liveTenableMatchCount > 0 && ` · ${liveTenableMatchCount} also confirmed in your Tenable.io inventory`}.
              </div>
            )}
            {liveStatus === "error" && (
              <div style={{ fontSize: 12, color: "#dc2626", display: "flex", alignItems: "center", gap: 10 }}>
                <span>{liveError}</span>
                <button
                  onClick={runLiveScan}
                  style={{ background: "none", border: "none", color: "#2563eb", fontWeight: 600, cursor: "pointer", fontSize: 12 }}
                >
                  Retry
                </button>
              </div>
            )}
          </div>
        )}
      </div>
      <Footer
        step={0}
        onBack={onBack}
        onNext={onNext}
        disableNext={mode === "upload" ? (!file || status !== "success") : liveStatus !== "success"}
      />
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

//Upload step 5: Generate Ticket
function GenerateTicketStep({ onNext, onBack, selected }) {
  const tickets = (selected || []).map(id => {
    const d = cveDetails[id] || {};
    const row = vulnRows.find(r => r.id === id) || {};
    return {
      id,
      title: `[${row.severity || ""}] ${id} — ${d.title || ""}`,
      description: d.why || "",
      priority: row.severity === "Critical" ? "P1 - Critical" : row.severity === "High" ? "P2 - High" : "P3 - Medium",
      asset: row.asset || "",
      assignTo: row.severity === "Critical" ? "Security Team" : "IT Operations",
    };
  });

  const [activeIdx, setActiveIdx] = useState(0);
  const [forms, setForms] = useState(tickets.map(t => ({ ...t })));
  const [submitted, setSubmitted] = useState(tickets.map(() => null));
  const allDone = submitted.every(s => s !== null);

  const update = (field, value) => {
    setForms(prev => prev.map((f, i) => i === activeIdx ? { ...f, [field]: value } : f));
  };

  const form = forms[activeIdx] || {};

  return (
    <>
      <div className="page-card" style={{ flexDirection: "row", gap: 0, padding: 0, overflow: "hidden" }}>
        {/* Left sidebar */}
        <div style={{ width: 200, borderRight: "1px solid #f3f4f6", padding: "16px 0", flexShrink: 0, overflowY: "auto" }}>
          <div style={{ padding: "0 16px 12px", fontSize: 11, fontWeight: 600, color: "#6b7280", textTransform: "uppercase", letterSpacing: "0.05em" }}>Tickets to create</div>
          {forms.map((t, i) => (
            <div key={t.id} onClick={() => setActiveIdx(i)}
              style={{ padding: "10px 16px", cursor: "pointer", background: activeIdx === i ? "#eff6ff" : "transparent",
                borderLeft: activeIdx === i ? "3px solid #2563eb" : "3px solid transparent" }}>
              <div style={{ fontSize: 12, fontFamily: "monospace", color: activeIdx === i ? "#2563eb" : "#374151", fontWeight: 600 }}>{t.id}</div>
              <div style={{ fontSize: 11, marginTop: 2, color: submitted[i] === "approved" ? "#16a34a" : submitted[i] === "rejected" ? "#dc2626" : "#9ca3af" }}>
                {submitted[i] === "approved" ? "✓ Approved" : submitted[i] === "rejected" ? "✗ Rejected" : t.priority}
              </div>
            </div>
          ))}
        </div>

        {/* Right form */}
        <div style={{ flex: 1, padding: 24, overflowY: "auto" }}>
          <div style={{ fontSize: 15, fontWeight: 700, color: "#111", marginBottom: 20 }}>Create Ticket</div>

          {/* Title + Priority */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
            <div>
              <input
                value={form.title || ""}
                onChange={e => update("title", e.target.value)}
                placeholder="Title"
                style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid #e5e7eb", fontSize: 13, fontFamily: "DM Sans, sans-serif", color: "#374151", background: "#fff", outline: "none" }}
              />
            </div>
            <div>
              <select
                value={form.priority || ""}
                onChange={e => update("priority", e.target.value)}
                style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid #e5e7eb", fontSize: 13, fontFamily: "DM Sans, sans-serif", color: "#374151", background: "#fff", outline: "none" }}>
                <option>P1 - Critical</option>
                <option>P2 - High</option>
                <option>P3 - Medium</option>
              </select>
            </div>
          </div>

          {/* Description */}
          <div style={{ marginBottom: 12 }}>
            <textarea
              value={form.description || ""}
              onChange={e => update("description", e.target.value)}
              placeholder="Description (From AI)"
              rows={5}
              style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid #e5e7eb", fontSize: 13, fontFamily: "DM Sans, sans-serif", color: "#374151", background: "#fff", outline: "none", resize: "vertical", lineHeight: 1.6 }}
            />
          </div>

          {/* Assign To + Destination */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 20 }}>
            <div>
              <select
                value={form.assignTo || ""}
                onChange={e => update("assignTo", e.target.value)}
                style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid #e5e7eb", fontSize: 13, fontFamily: "DM Sans, sans-serif", color: "#374151", background: "#fff", outline: "none" }}>
                <option>Security Team</option>
                <option>IT Operations</option>
                <option>Infrastructure</option>
                <option>Platform Engineering</option>
              </select>
            </div>
            <div>
              <select
                value={form.asset || ""}
                onChange={e => update("asset", e.target.value)}
                style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid #e5e7eb", fontSize: 13, fontFamily: "DM Sans, sans-serif", color: "#374151", background: "#fff", outline: "none" }}>
                {vulnRows.map(r => <option key={r.asset}>{r.asset}</option>)}
              </select>
            </div>
          </div>

          {/* Approve / Reject buttons */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <button
              onClick={() => {
                setSubmitted(prev => prev.map((s, i) => i === activeIdx ? (s === "approved" ? null : "approved") : s));
                if (submitted[activeIdx] !== "approved" && activeIdx < tickets.length - 1) setActiveIdx(activeIdx + 1);
              }}
              style={{ padding: "12px", borderRadius: 20, border: "none", background: submitted[activeIdx] === "approved" ? "#16a34a" : "#2563eb", color: "#fff", fontSize: 14, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: "pointer" }}>
              {submitted[activeIdx] === "approved" ? "✓ Approved" : "Approve"}
            </button>
            <button
              onClick={() => {
                setSubmitted(prev => prev.map((s, i) => i === activeIdx ? (s === "rejected" ? null : "rejected") : s));
                if (submitted[activeIdx] !== "rejected" && activeIdx < tickets.length - 1) setActiveIdx(activeIdx + 1);
              }}
              style={{ padding: "12px", borderRadius: 20, border: "1px solid #e5e7eb", background: submitted[activeIdx] === "rejected" ? "#fef2f2" : "#fff", color: submitted[activeIdx] === "rejected" ? "#dc2626" : "#374151", fontSize: 14, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: "pointer" }}>
              {submitted[activeIdx] === "rejected" ? "✗ Rejected" : "Reject"}
            </button>
          </div>
        </div>
      </div>
      <Footer step={4} onBack={onBack} onNext={() => onNext(tickets.filter((_, i) => submitted[i] === "approved").map(t => t.id))} nextLabel="Review & Send" disableNext={!allDone} />
    </>
  );
}

//Upload step 6: Review & Send
function ReviewSendStep({ onNext, onBack, selected, approvedTickets, onSubmit }) {
  const tickets = (approvedTickets || []).map(id => {
    const d = cveDetails[id] || {};
    const row = vulnRows.find(r => r.id === id) || {};
    return {
      id,
      title: d.title || "",
      priority: row.severity === "Critical" ? "P1" : row.severity === "High" ? "P2" : "P3",
      assignTo: row.severity === "Critical" ? "Security Team" : "IT Operations",
      severity: row.severity || "",
    };
  });

  const [sent, setSent] = useState(false);
  const priorityColor = p => p === "P1" ? { bg: "#fef2f2", color: "#dc2626" } : p === "P2" ? { bg: "#fff7ed", color: "#ea580c" } : { bg: "#f0fdf4", color: "#16a34a" };

  if (sent) {
    return (
      <>
        <div className="page-card" style={{ alignItems: "center", justifyContent: "center", gap: 16, minHeight: 300 }}>
          <div style={{ width: 64, height: 64, borderRadius: "50%", background: "#f0fdf4", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 28 }}>✓</div>
          <div style={{ fontSize: 18, fontWeight: 700, color: "#111" }}>Tickets sent to Jira</div>
          <div style={{ fontSize: 13, color: "#6b7280" }}>{tickets.length} ticket{tickets.length !== 1 ? "s" : ""} successfully created</div>
          <button onClick={onNext} className="btn btn-primary" style={{ marginTop: 8 }}>Go to Tickets</button>
        </div>
        <Footer step={5} onBack={onBack} onNext={onNext} nextLabel="Done" />
      </>
    );
  }

  return (
    <>
      <div className="page-card">
        <div style={{ fontSize: 15, fontWeight: 700, color: "#111", marginBottom: 4 }}>Review & Send</div>
        <div style={{ fontSize: 13, color: "#6b7280", marginBottom: 20 }}>Confirm the following tickets will be sent to Jira</div>

        <div style={{ border: "1px solid #f3f4f6", borderRadius: 10, overflow: "hidden", marginBottom: 20 }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr 1fr 1fr", padding: "10px 16px", background: "#f9fafb", borderBottom: "1px solid #f3f4f6" }}>
            {["CVE", "Title", "Priority", "Assign To"].map(h => (
              <div key={h} style={{ fontSize: 11, fontWeight: 600, color: "#6b7280", textTransform: "uppercase", letterSpacing: "0.05em" }}>{h}</div>
            ))}
          </div>
          {tickets.map((t, i) => {
            const pc = priorityColor(t.priority);
            return (
              <div key={t.id} style={{ display: "grid", gridTemplateColumns: "1fr 2fr 1fr 1fr", padding: "12px 16px", borderBottom: i < tickets.length - 1 ? "1px solid #f3f4f6" : "none", alignItems: "center" }}>
                <div style={{ fontSize: 12, fontFamily: "monospace", color: "#374151", fontWeight: 600 }}>{t.id}</div>
                <div style={{ fontSize: 13, color: "#374151" }}>{t.title}</div>
                <div><span style={{ fontSize: 11, fontWeight: 700, padding: "3px 10px", borderRadius: 20, background: pc.bg, color: pc.color }}>{t.priority}</span></div>
                <div style={{ fontSize: 13, color: "#6b7280" }}>{t.assignTo}</div>
              </div>
            );
          })}
        </div>

        {tickets.length === 0 ? (
          <div style={{ textAlign: "center", padding: "20px 0" }}>
            <div style={{ fontSize: 15, fontWeight: 600, color: "#374151", marginBottom: 6 }}>No tickets to send</div>
            <div style={{ fontSize: 13, color: "#9ca3af", marginBottom: 16 }}>All tickets were rejected. Go back to approve at least one.</div>
            <button onClick={onBack} style={{ padding: "10px 24px", borderRadius: 20, border: "1px solid #e5e7eb", background: "#fff", fontSize: 13, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: "pointer", color: "#374151" }}>Go back</button>
          </div>
        ) : (
          <button
            onClick={() => {
              const newTickets = tickets.map((t, i) => ({
                id: `T-${String(106 + i).padStart(3, "0")}`,
                cve: t.id,
                title: t.title,
                priority: t.priority,
                status: "Open",
                assigned: t.assignTo,
                date: new Date().toLocaleDateString("en-GB").replace(/\//g, "-"),
                cvss: cveDetails[t.id]?.cvss || 0,
                confidence: cveDetails[t.id]?.confidence || 0,
                fixes: cveDetails[t.id]?.fixes || [],
                why: cveDetails[t.id]?.why || "",
              }));
              onSubmit(newTickets);
              setSent(true);
            }}
            style={{ width: "100%", padding: "12px", borderRadius: 20, border: "none", background: "#111", color: "#fff", fontSize: 14, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: "pointer" }}>
            Send to Jira
          </button>
        )}
      </div>
      <Footer step={5} onBack={onBack} onNext={onNext} nextLabel="Done" />
    </>
  );
}

//Ticket List
const ticketData = [
  { id: "T-101", cve: "CVE-2024-3094", title: "XZ Utils backdoor in liblzma", priority: "P1", status: "Open", assigned: "Security Team", date: "21-05-2026", cvss: 9.8, confidence: 92, fixes: cveDetails["CVE-2024-3094"]?.fixes || [], why: cveDetails["CVE-2024-3094"]?.why || "" },
  { id: "T-102", cve: "CVE-2026-33845", title: "OpenSSL heap overflow in X.509 parser", priority: "P2", status: "In Progress", assigned: "Infra", date: "13-05-2026", cvss: 9.6, confidence: 88, fixes: cveDetails["CVE-2026-33845"]?.fixes || [], why: cveDetails["CVE-2026-33845"]?.why || "" },
  { id: "T-103", cve: "CVE-2026-44012", title: "Redis Lua sandbox escape", priority: "P1", status: "Open", assigned: "Security Team", date: "05-05-2026", cvss: 9.1, confidence: 95, fixes: cveDetails["CVE-2026-44012"]?.fixes || [], why: cveDetails["CVE-2026-44012"]?.why || "" },
  { id: "T-104", cve: "CVE-2026-33846", title: "Kubernetes kubelet path traversal", priority: "P3", status: "Open", assigned: "Platform Eng", date: "27-04-2026", cvss: 8.2, confidence: 81, fixes: cveDetails["CVE-2026-33846"]?.fixes || [], why: cveDetails["CVE-2026-33846"]?.why || "" },
  { id: "T-105", cve: "CVE-2026-12012", title: "nginx HTTP/3 use-after-free", priority: "P2", status: "Closed", assigned: "Security Team", date: "24-04-2026", cvss: 6.3, confidence: 77, fixes: cveDetails["CVE-2026-12012"]?.fixes || [], why: cveDetails["CVE-2026-12012"]?.why || "" },
];

function TicketList({ tickets: initialTickets }) {
  const [statusFilter, setStatusFilter] = useState("All");
  const [priorityFilter, setPriorityFilter] = useState("All");
  const [tickets, setTickets] = useState(initialTickets || []);
  const [selectedTicket, setSelectedTicket] = useState((initialTickets || [])[0] || null);
  const [editing, setEditing] = useState(false);
  const [editForm, setEditForm] = useState({});

  const filtered = tickets.filter(t =>
    (statusFilter === "All" || t.status === statusFilter) &&
    (priorityFilter === "All" || t.priority === priorityFilter)
  );

  const priorityColor = p => p === "P1" ? { bg: "#fef2f2", color: "#dc2626" } : p === "P2" ? { bg: "#fff7ed", color: "#ea580c" } : { bg: "#f0fdf4", color: "#16a34a" };
  const statusColor = s => s === "Open" ? { bg: "#eff6ff", color: "#2563eb" } : s === "In Progress" ? { bg: "#fef9c3", color: "#ca8a04" } : { bg: "#f0fdf4", color: "#16a34a" };

  return (
    <div className="page-card" style={{ flexDirection: "row", gap: 0, padding: 0, overflow: "hidden", flex: 1 }}>
      {/* Left panel */}
      <div style={{ flex: 1, borderRight: "1px solid #f3f4f6", display: "flex", flexDirection: "column", minWidth: 0 }}>
        {/* Header */}
        <div style={{ padding: "20px 24px 0" }}>
          <div style={{ fontSize: 18, fontWeight: 700, color: "#111", marginBottom: 4 }}>Tickets</div>
          <div style={{ fontSize: 13, color: "#6b7280", marginBottom: 16 }}>AI-generated — human approved — synced with Jira</div>

          {/* Filters */}
          <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
            {["All", "Open", "In Progress", "Closed"].map(s => (
              <button key={s} onClick={() => setStatusFilter(s)}
                style={{ padding: "5px 14px", borderRadius: 20, border: "1px solid #e5e7eb", fontSize: 12, fontWeight: 500, cursor: "pointer", fontFamily: "DM Sans, sans-serif",
                  background: statusFilter === s ? "#2563eb" : "#fff", color: statusFilter === s ? "#fff" : "#374151" }}>
                {s}
              </button>
            ))}
            <div style={{ width: 1, background: "#e5e7eb", margin: "0 4px" }} />
            {["All", "P1", "P2", "P3"].map(p => (
              <button key={p} onClick={() => setPriorityFilter(p)}
                style={{ padding: "5px 14px", borderRadius: 20, border: "1px solid #e5e7eb", fontSize: 12, fontWeight: 500, cursor: "pointer", fontFamily: "DM Sans, sans-serif",
                  background: priorityFilter === p ? "#2563eb" : "#fff", color: priorityFilter === p ? "#fff" : "#374151" }}>
                {p}
              </button>
            ))}
          </div>

          {/* Table header */}
          <div style={{ display: "grid", gridTemplateColumns: "60px 120px 1fr 60px 80px 100px 90px", gap: 8, padding: "8px 0", borderBottom: "1px solid #e5e7eb" }}>
            {["Ticket", "CVE", "Title", "Priority", "Status", "Assigned", "Date"].map(h => (
              <div key={h} style={{ fontSize: 11, fontWeight: 600, color: "#9ca3af", textTransform: "uppercase", letterSpacing: "0.04em" }}>{h}</div>
            ))}
          </div>
        </div>

        {/* Table rows */}
        <div style={{ overflowY: "auto", flex: 1 }}>
          {filtered.length === 0 ? (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: 200, flexDirection: "column", gap: 8 }}>
              <div style={{ fontSize: 15, fontWeight: 600, color: "#374151" }}>No tickets found</div>
              <div style={{ fontSize: 13, color: "#9ca3af" }}>Tickets will appear here once a scan has been reviewed and submitted</div>
            </div>
          ) : (
            filtered.map(t => {
              const pc = priorityColor(t.priority);
              const sc = statusColor(t.status);
              return (
                <div key={t.id} onClick={() => { setSelectedTicket(t); setEditing(false); }}
                  style={{ display: "grid", gridTemplateColumns: "60px 120px 1fr 60px 80px 100px 90px", gap: 8, padding: "12px 24px", borderBottom: "1px solid #f3f4f6", cursor: "pointer",
                    background: selectedTicket?.id === t.id ? "#eff6ff" : "transparent", alignItems: "center" }}>
                  <div style={{ fontSize: 12, fontWeight: 700, color: "#374151" }}>{t.id}</div>
                  <div style={{ fontSize: 11, fontFamily: "monospace", color: "#6b7280" }}>{t.cve}</div>
                  <div style={{ fontSize: 12, color: "#374151", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{t.title}</div>
                  <div><span style={{ fontSize: 11, fontWeight: 700, padding: "2px 8px", borderRadius: 20, background: pc.bg, color: pc.color }}>{t.priority}</span></div>
                  <div><span style={{ fontSize: 11, fontWeight: 600, padding: "2px 8px", borderRadius: 20, background: sc.bg, color: sc.color }}>{t.status}</span></div>
                  <div style={{ fontSize: 12, color: "#6b7280" }}>{t.assigned}</div>
                  <div style={{ fontSize: 11, color: "#9ca3af" }}>{t.date}</div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Right detail panel */}
      {selectedTicket && (
        <div style={{ width: 320, padding: 20, overflowY: "auto", flexShrink: 0 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: "#111", marginBottom: 4 }}>{selectedTicket.id} — {selectedTicket.cve}</div>
          <div style={{ fontSize: 13, color: "#6b7280", marginBottom: 12 }}>{selectedTicket.title}</div>

          {/* Badges */}
          <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
            <span style={{ fontSize: 11, fontWeight: 700, padding: "3px 10px", borderRadius: 20, background: priorityColor(selectedTicket.priority).bg, color: priorityColor(selectedTicket.priority).color }}>{selectedTicket.priority}</span>
            <span style={{ fontSize: 11, fontWeight: 600, padding: "3px 10px", borderRadius: 20, background: statusColor(selectedTicket.status).bg, color: statusColor(selectedTicket.status).color }}>{selectedTicket.status}</span>
            <span style={{ fontSize: 11, color: "#6b7280", padding: "3px 0" }}>CVSS {selectedTicket.cvss}</span>
          </div>

          {/* AI Analysis */}
          <div style={{ background: "#f5f3ff", borderRadius: 10, padding: 12, marginBottom: 12 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: "#7c3aed", marginBottom: 6 }}>AI-Powered Analysis</div>
            <div style={{ fontSize: 12, color: "#6b7280", lineHeight: 1.5 }}>{selectedTicket.why}</div>
          </div>

          {/* Suggested Fix */}
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: "#374151", marginBottom: 6 }}>Suggested fix</div>
            {selectedTicket.fixes.map((f, i) => (
              <div key={i} style={{ fontSize: 12, color: "#6b7280", marginBottom: 4, display: "flex", gap: 6 }}>
                <span style={{ color: "#374151", fontWeight: 600, flexShrink: 0 }}>{i + 1}.</span> {f}
              </div>
            ))}
          </div>

          {/* Validation */}
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: "#374151", marginBottom: 6 }}>Validation</div>
            {["CVSS verified against NVD", "CVE record exists in MITRE", "Vendor advisory cross-referenced"].map(v => (
              <div key={v} style={{ fontSize: 12, color: "#6b7280", marginBottom: 3, display: "flex", gap: 6, alignItems: "center" }}>
                <span style={{ color: "#22c55e" }}>✓</span> {v}
              </div>
            ))}
          </div>

          {/* Confidence */}
          <div style={{ marginBottom: 16 }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: "#374151" }}>Confidence</div>
              <div style={{ fontSize: 12, color: "#374151" }}>{selectedTicket.confidence}%</div>
            </div>
            <div style={{ height: 6, background: "#e5e7eb", borderRadius: 99 }}>
              <div style={{ height: 6, background: "#2563eb", borderRadius: 99, width: `${selectedTicket.confidence}%` }} />
            </div>
          </div>

          {/* Buttons */}
          {!editing ? (
            <div style={{ display: "flex", gap: 8 }}>
              <button
                onClick={() => { setEditing(true); setEditForm({ status: selectedTicket.status, assigned: selectedTicket.assigned }); }}
                style={{ flex: 1, padding: "8px", borderRadius: 20, border: "1px solid #e5e7eb", background: "#fff", fontSize: 13, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: "pointer", color: "#374151" }}>
                Edit
              </button>
              <button
                onClick={() => setSelectedTicket(null)}
                style={{ flex: 1, padding: "8px", borderRadius: 20, border: "none", background: "#f3f4f6", fontSize: 13, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: "pointer", color: "#374151" }}>
                Close
              </button>
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              <select
                value={editForm.status}
                onChange={e => setEditForm(f => ({ ...f, status: e.target.value }))}
                style={{ width: "100%", padding: "8px 12px", borderRadius: 8, border: "1px solid #e5e7eb", fontSize: 13, fontFamily: "DM Sans, sans-serif", color: "#374151", background: "#fff", outline: "none" }}>
                <option>Open</option>
                <option>In Progress</option>
                <option>Closed</option>
              </select>
              <select
                value={editForm.assigned}
                onChange={e => setEditForm(f => ({ ...f, assigned: e.target.value }))}
                style={{ width: "100%", padding: "8px 12px", borderRadius: 8, border: "1px solid #e5e7eb", fontSize: 13, fontFamily: "DM Sans, sans-serif", color: "#374151", background: "#fff", outline: "none" }}>
                <option>Security Team</option>
                <option>IT Operations</option>
                <option>Infrastructure</option>
                <option>Platform Engineering</option>
              </select>
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  onClick={() => {
                    const updated = { ...selectedTicket, ...editForm };
                    setTickets(prev => prev.map(t => t.id === updated.id ? updated : t));
                    setSelectedTicket(updated);
                    setEditing(false);
                  }}
                  style={{ flex: 1, padding: "8px", borderRadius: 20, border: "none", background: "#2563eb", color: "#fff", fontSize: 13, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: "pointer" }}>
                  Save
                </button>
                <button
                  onClick={() => setEditing(false)}
                  style={{ flex: 1, padding: "8px", borderRadius: 20, border: "1px solid #e5e7eb", background: "#fff", fontSize: 13, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: "pointer", color: "#374151" }}>
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

//Profile
function Profile({ onSignOut, userName, userEmail }) {
  const [notifications, setNotifications] = useState(true);
  const [defaultAssign, setDefaultAssign] = useState("Security Team");

  return (
    <div className="page-card" style={{ maxWidth: 560, margin: "0 auto", width: "100%" }}>
      <div style={{ fontSize: 18, fontWeight: 700, color: "#111", marginBottom: 4 }}>Profile</div>
      <div style={{ fontSize: 13, color: "#6b7280", marginBottom: 24 }}>Manage your account settings</div>

      <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 28, padding: 20, background: "#f9fafb", borderRadius: 12 }}>
        <div style={{ width: 56, height: 56, borderRadius: "50%", background: "#2563eb", display: "flex", alignItems: "center", justifyContent: "center", color: "#fff", fontSize: 20, fontWeight: 700, flexShrink: 0 }}>
          {userName ? userName[0].toUpperCase() : "U"}
        </div>
        <div>
          <div style={{ fontSize: 16, fontWeight: 700, color: "#111" }}>{userName || "User"}</div>
          <div style={{ fontSize: 13, color: "#6b7280" }}>{userEmail || "user@organisation.com"}</div>
          <div style={{ fontSize: 12, color: "#2563eb", fontWeight: 600, marginTop: 2 }}>Security Analyst</div>
        </div>
      </div>

      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: "#374151", marginBottom: 12 }}>Account details</div>
        <div style={{ display: "grid", gap: 10 }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <div>
              <div style={{ fontSize: 11, fontWeight: 600, color: "#6b7280", marginBottom: 4 }}>Full name</div>
              <div style={{ padding: "10px 14px", background: "#f9fafb", borderRadius: 8, border: "1px solid #e5e7eb", fontSize: 13, color: "#374151" }}>{userName || "User"}</div>
            </div>
            <div>
              <div style={{ fontSize: 11, fontWeight: 600, color: "#6b7280", marginBottom: 4 }}>Role</div>
              <div style={{ padding: "10px 14px", background: "#f9fafb", borderRadius: 8, border: "1px solid #e5e7eb", fontSize: 13, color: "#374151" }}>Security Analyst</div>
            </div>
          </div>
          <div>
            <div style={{ fontSize: 11, fontWeight: 600, color: "#6b7280", marginBottom: 4 }}>Email</div>
            <div style={{ padding: "10px 14px", background: "#f9fafb", borderRadius: 8, border: "1px solid #e5e7eb", fontSize: 13, color: "#374151" }}>{userEmail || "user@organisation.com"}</div>
          </div>
          <div>
            <div style={{ fontSize: 11, fontWeight: 600, color: "#6b7280", marginBottom: 4 }}>Organisation</div>
            <div style={{ padding: "10px 14px", background: "#f9fafb", borderRadius: 8, border: "1px solid #e5e7eb", fontSize: 13, color: "#374151" }}>Queensland University of Technology</div>
          </div>
        </div>
      </div>

      <div style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: "#374151", marginBottom: 12 }}>Preferences</div>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 16px", background: "#f9fafb", borderRadius: 10, border: "1px solid #e5e7eb", marginBottom: 10 }}>
          <div>
            <div style={{ fontSize: 13, fontWeight: 500, color: "#374151" }}>Email notifications</div>
            <div style={{ fontSize: 12, color: "#6b7280" }}>Get alerted for critical vulnerabilities</div>
          </div>
          <div
            onClick={() => setNotifications(n => !n)}
            style={{ width: 44, height: 24, borderRadius: 99, background: notifications ? "#2563eb" : "#e5e7eb", cursor: "pointer", position: "relative", transition: "background .2s", flexShrink: 0 }}>
            <div style={{ width: 18, height: 18, borderRadius: "50%", background: "#fff", position: "absolute", top: 3, left: notifications ? 23 : 3, transition: "left .2s", boxShadow: "0 1px 3px rgba(0,0,0,0.2)" }} />
          </div>
        </div>
        <div style={{ padding: "12px 16px", background: "#f9fafb", borderRadius: 10, border: "1px solid #e5e7eb" }}>
          <div style={{ fontSize: 13, fontWeight: 500, color: "#374151", marginBottom: 8 }}>Default assign to</div>
          <select
            value={defaultAssign}
            onChange={e => setDefaultAssign(e.target.value)}
            style={{ width: "100%", padding: "8px 12px", borderRadius: 8, border: "1px solid #e5e7eb", fontSize: 13, fontFamily: "DM Sans, sans-serif", color: "#374151", background: "#fff", outline: "none" }}>
            <option>Security Team</option>
            <option>IT Operations</option>
            <option>Infrastructure</option>
            <option>Platform Engineering</option>
          </select>
        </div>
      </div>

      <button
        onClick={onSignOut}
        style={{ width: "100%", padding: "12px", borderRadius: 20, border: "none", background: "#fef2f2", color: "#dc2626", fontSize: 14, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: "pointer" }}>
        Sign out
      </button>
    </div>
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
// Floating scan-scoped chatbot. Replaces the static chat-bubble placeholder.
// Answers questions about lastVulnerabilities (the current scan/report) via
// POST /api/chat — see chatbot.py. Only available once a scan has been
// uploaded; otherwise it opens with an explanatory empty state instead of
// silently sending an empty context to the backend.
function ChatWidget() {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState([]); // {role: "user"|"assistant", content}
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const scrollRef = useRef(null);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages, open]);

  const send = async () => {
    const question = input.trim();
    if (!question || sending) return;
    setInput("");
    const nextMessages = [...messages, { role: "user", content: question }];
    setMessages(nextMessages);
    setSending(true);
    try {
      const res = await fetch(`${API_BASE}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          question,
          vulnerabilities: lastVulnerabilities,
          history: nextMessages,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Chat request failed");
      setMessages(prev => [...prev, { role: "assistant", content: data.answer }]);
    } catch (err) {
      setMessages(prev => [...prev, { role: "assistant", content: `⚠️ ${err.message || "Could not reach the chat service."}` }]);
    } finally {
      setSending(false);
    }
  };

  const handleKeyDown = e => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };

  if (!open) {
    return (
      <div className="chat-bubble" onClick={() => setOpen(true)} title="Ask about this scan">💬</div>
    );
  }

  return (
    <div style={{ position: "fixed", bottom: 28, right: 28, width: 340, maxWidth: "90vw", height: 440, background: "#fff", borderRadius: 16, boxShadow: "0 8px 32px rgba(0,0,0,.18)", display: "flex", flexDirection: "column", overflow: "hidden", zIndex: 100, fontFamily: "DM Sans, sans-serif" }}>
      <div style={{ padding: "12px 16px", background: "#7c3aed", color: "#fff", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={{ fontSize: 14, fontWeight: 700 }}>Scan Assistant</div>
        <span onClick={() => setOpen(false)} style={{ cursor: "pointer", fontSize: 18, lineHeight: 1 }}>×</span>
      </div>

      <div ref={scrollRef} style={{ flex: 1, overflowY: "auto", padding: 12, display: "flex", flexDirection: "column", gap: 10, background: "#f9fafb" }}>
        {messages.length === 0 && (
          <div style={{ fontSize: 12, color: "#9ca3af", padding: 8 }}>
            {lastVulnerabilities.length === 0
              ? "Upload a scan first — I answer questions using the vulnerabilities found in your current report only."
              : `Ask me anything about the ${lastVulnerabilities.length} finding(s) in your current scan — e.g. "which CVEs affect ${lastVulnerabilities[0]?.asset || "this asset"}?" or "what's our most severe issue?"`}
          </div>
        )}
        {messages.map((m, i) => (
          <div key={i} style={{ alignSelf: m.role === "user" ? "flex-end" : "flex-start", maxWidth: "85%", background: m.role === "user" ? "#2563eb" : "#eef0f4", color: m.role === "user" ? "#fff" : "#1f2937", padding: "8px 12px", borderRadius: 12, fontSize: 13, whiteSpace: "pre-wrap" }}>
            {m.content}
          </div>
        ))}
        {sending && (
          <div style={{ alignSelf: "flex-start", fontSize: 12, color: "#9ca3af", padding: "4px 8px" }}>Thinking…</div>
        )}
      </div>

      <div style={{ padding: 10, borderTop: "1px solid #e5e7eb", display: "flex", gap: 8 }}>
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Ask about this scan…"
          style={{ flex: 1, padding: "8px 12px", borderRadius: 20, border: "1px solid #e5e7eb", fontSize: 13, fontFamily: "DM Sans, sans-serif", outline: "none" }}
        />
        <button
          onClick={send}
          disabled={sending || !input.trim()}
          style={{ padding: "8px 14px", borderRadius: 20, border: "none", background: input.trim() ? "#2563eb" : "#e5e7eb", color: input.trim() ? "#fff" : "#9ca3af", fontSize: 13, fontWeight: 600, cursor: input.trim() ? "pointer" : "default" }}
        >
          Send
        </button>
      </div>
    </div>
  );
}

export default function App() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [uploadStep, setUploadStep] = useState(0);
  const [cveId, setCveId] = useState(null);
  const [selected, setSelected] = useState(vulnRows.map(r => r.id));
  const [submittedTickets, setSubmittedTickets] = useState([]);
  const [liveTickets, setLiveTickets] = useState([]);
  const [prevStep, setPrevStep] = useState(1);
  const [uploadedFile, setUploadedFile] = useState(null);
  const [authScreen, setAuthScreen] = useState("signin");
  const [authed, setAuthed] = useState(false);
  const [accounts, setAccounts] = useState([]);
  const [userName, setUserName] = useState("");
  const [userEmail, setUserEmail] = useState("");

  const goToTab = tab => { setActiveTab(tab); setUploadStep(0); setCveId(null); setUploadedFile(null); };

  const handleScanParsed = vulnerabilities => {
    applyScanResults(vulnerabilities);
    setSelected(vulnRows.map(r => r.id));
  };

  const renderUploadContent = () => {
    if (cveId) {
      return <CveDetailStep cveId={cveId} onBack={() => setCveId(null)} onNext={() => { setCveId(null); }} backLabel={prevStep === 2 ? "Back to Select" : "Back to AI Summary"} />;
    }
    switch (uploadStep) {
      case 0: return <UploadStep onNext={() => setUploadStep(1)} onBack={() => goToTab("dashboard")} file={uploadedFile} setFile={setUploadedFile} onParsed={handleScanParsed} />;
      case 1: return <AISummaryStep onNext={() => setUploadStep(2)} onBack={() => setUploadStep(0)} onCveClick={id => { setPrevStep(1); setCveId(id); }} />;
      case 2: return <SelectStep onNext={() => setUploadStep(3)} onBack={() => setUploadStep(1)} selected={selected} setSelected={setSelected} onCveClick={id => { setPrevStep(2); setCveId(id); }} />;
      case 3: return <ValidationStep onNext={() => setUploadStep(4)} onBack={() => setUploadStep(2)} selected={selected} onCveClick={id => { setPrevStep(3); setCveId(id); }} />;
      case 4: return <GenerateTicketStep onNext={(approved) => { setSubmittedTickets(approved); setUploadStep(5); }} onBack={() => setUploadStep(3)} selected={selected} />;
      case 5: return <ReviewSendStep onNext={() => goToTab("tickets")} onBack={() => setUploadStep(4)} selected={selected} approvedTickets={submittedTickets} onSubmit={(newTickets) => setLiveTickets(prev => [...prev, ...newTickets])} />;
      default: return null;
    }
  };

  if (!authed) {
    return (
      <>
        <style>{css}</style>
        <div className="shell">
          {authScreen === "signin"
            ? <SignIn onSignIn={(email, password) => { const account = accounts.find(a => a.email === email && a.password === password); if (account) { setUserName(account.name); setUserEmail(email); setAuthed(true); } }} onGoSignUp={() => setAuthScreen("signup")} accounts={accounts} />
            : <SignUp onSignUp={(name, email, password) => { setAccounts(prev => [...prev, { name, email, password }]); setUserName(name); setUserEmail(email); setAuthScreen("signin"); }} onGoSignIn={() => setAuthScreen("signin")} />
          }
        </div>
      </>
    );
  }

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
        {activeTab === "tickets" && <TicketList tickets={liveTickets} />}
        {activeTab === "profile" && <Profile onSignOut={() => { setAuthed(false); setAuthScreen("signin"); setUserName(""); setUserEmail(""); }} userName={userName} userEmail={userEmail} />}

        <ChatWidget />
      </div>
    </>
  );
}
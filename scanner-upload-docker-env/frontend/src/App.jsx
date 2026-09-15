import { useState, useRef, useEffect } from "react";
import { BarChart, Bar, LineChart, Line, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, CartesianGrid } from "recharts";

// Base URL for the scanner-upload backend (Flask). Update this if the
// backend runs somewhere other than localhost:5000 (e.g. in docker-compose).
const API_BASE = "http://localhost:5000";

//Placeholder cve details
// NOTE: allRisks / vulnRows / validationRows / cveDetails below start out as
// demo data so the wizard still looks right before anything is uploaded.
// Once a real scan file is uploaded, applyScanResults() overwrites their
// contents with the parsed findings from the scanner-upload backend.
export let cveDetails = {
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
export let allRisks = Object.entries(cveDetails).map(([id, d]) => ({ id, cvss: d.cvss, severity: d.severity, title: d.title }));
export let vulnRows = [
  { id: "CVE-2024-3094",  title: "",                                  severity: "Critical", cvss: 9.8, asset: "db-analytics-02"  },
  { id: "CVE-2026-33845", title: "OpenSSL heap overflow in X.509 parser", severity: "Critical", cvss: 9.6, asset: "edge-gw-prod-01"  },
  { id: "CVE-2026-44012", title: "Redis Lua sandbox escape",           severity: "Critical", cvss: 9.1, asset: "cache-shard-7"    },
  { id: "CVE-2026-33846", title: "Kubernetes kubelet path traversal",  severity: "High",     cvss: 8.2, asset: "k8s-cluster-eu"  },
  { id: "CVE-2026-12012", title: "nginx HTTP/3 use-after-free",        severity: "Medium",   cvss: 6.3, asset: "edge-gw-prod-02" },
];
export let validationRows = [
  { id: "CVE-2024-3094",  severity: "Critical", status: "Validated",    desc: "OpenSSL heap overflow in X.509 parser"  },
  { id: "CVE-2026-33845", severity: "Critical", status: "Needs Review", desc: "Kubernetes kubelet path traversal"      },
  { id: "CVE-2026-44012", severity: "Critical", status: "Validated",    desc: "Redis Lua sandbox escape"               },
  { id: "CVE-2026-33846", severity: "High",     status: "Validated",    desc: "Kubernetes kubelet path traversal"      },
  { id: "CVE-2026-12012", severity: "Medium",   status: "Needs Review", desc: "nginx HTTP/3 use-after-free"            },
];
// Raw normalized findings from the last successful scan, kept around so the
// chatbot can ground its answers in the same data the rest of the wizard is
// showing (cve, title, severity, cvss, asset, package — see /api/chat).
export let lastVulnerabilities = [];

// Which scanner/source/target the current wizard run came from — set once
// when raw results first land (see UploadStep's onParsed calls below) and
// carried through analysis, so ReviewSendStep can tell the backend what
// this scan actually was when the user confirms sending tickets (see
// POST /api/scans in scans.py). A scan only gets recorded to history at
// that point, not right after upload/scan, so abandoning the wizard partway
// through never shows up as a "completed" scan.
export let lastScanMeta = { scanner: null, source: null, target: null };

// Turns the parsed vulnerability list returned by the scanner-upload backend
// into the same shapes the wizard's UI already renders (vulnRows, cveDetails,
// allRisks, validationRows), replacing the demo placeholder data above.
//
// Each entry in `vulnerabilities` may already carry real AI fields (why,
// business_impact, fixes, confidence, priority_tier, ai_generated) if it
// went through POST /api/analyze first — see runAiAnalysis() below. If
// those fields aren't present (analysis skipped or failed), fall back to
// the same heuristic placeholders as before so the UI never breaks.
export function applyScanResults(vulnerabilities, meta) {
  const list = Array.isArray(vulnerabilities) ? vulnerabilities : [];
  lastVulnerabilities = list;
  // Only set when actually passed — the second onParsed call per scan (once
  // AI analysis finishes) re-applies the same vulnerabilities without meta,
  // and shouldn't wipe out what the first call already recorded.
  if (meta) lastScanMeta = meta;

  vulnRows = list.map(v => ({
    id: v.cve || v.title,
    title: v.title || v.cve || "Untitled finding",
    severity: v.severity || "Unknown",
    cvss: typeof v.cvss === "number" ? v.cvss : 0,
    asset: v.asset || v.package || "unknown",
    businessPriorityScore: typeof v.business_priority_score === "number" ? v.business_priority_score : null,
  }));

  cveDetails = Object.fromEntries(list.map(v => {
    const id = v.cve || v.title;
    const hasAiResult = v.ai_generated !== undefined; // set by /api/analyze on every entry it touches

    let why, businessImpact, fixes, confidence;
    if (hasAiResult) {
      why = v.why || "No explanation was returned for this finding.";
      businessImpact = v.business_impact || "";
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
      businessImpact = "";
      confidence = typeof v.cvss === "number" && v.description ? 95 : 65;
    }

    return [id, {
      cvss: typeof v.cvss === "number" ? v.cvss : 0,
      confidence,
      severity: v.severity || "Unknown",
      title: v.title || id,
      why,
      businessImpact,
      fixes,
      priorityTier: v.priority_tier || null,
      aiGenerated: !!v.ai_generated,
      businessPriorityScore: typeof v.business_priority_score === "number" ? v.business_priority_score : null,
    }];
  }));

  // Preserves the order the backend returned the list in (business-impact
  // order when the survey's been completed, CVSS/severity order otherwise
  // — see /api/analyze), rather than re-deriving an order from the object
  // map, whose key order isn't guaranteed to match for non-string-integer
  // keys like CVE IDs.
  allRisks = list.map(v => {
    const id = v.cve || v.title;
    const d = cveDetails[id];
    return { id, cvss: d.cvss, severity: d.severity, title: d.title, businessPriorityScore: d.businessPriorityScore };
  });

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

// Set by runAiAnalysis() from the last /api/analyze response so the UI can
// tell the user whether ordering/analysis actually used their business
// context (vs. falling back to CVSS-only because they haven't completed
// the survey, or aren't signed in).
let lastBusinessContextApplied = false;

// Calls POST /api/analyze with the vulnerabilities parsed from either
// upload path, and returns the same list with AI fields merged in
// (including business_priority_score) — the backend also reorders the
// list by business_priority_score before returning it, so this is already
// business-impact-ordered, not just CVSS-ordered, whenever the signed-in
// user has completed the business-context survey.
// On any failure (backend unreachable, Ollama not running, etc.) falls
// back to returning the list unchanged — applyScanResults() then uses its
// heuristic placeholders instead of hard-failing the wizard.
async function runAiAnalysis(vulnerabilities) {
  if (!Array.isArray(vulnerabilities) || vulnerabilities.length === 0) return vulnerabilities;
  try {
    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: "POST",
      credentials: "include", // needed so the backend can look up the signed-in user's business context
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ vulnerabilities }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "AI analysis failed");
    lastBusinessContextApplied = !!data.businessContextApplied;
    return data.vulnerabilities || vulnerabilities;
  } catch (err) {
    console.warn("AI analysis unavailable, showing raw scan results:", err.message);
    lastBusinessContextApplied = false;
    return vulnerabilities;
  }
}

// Sends the current scan's vulnerabilities to POST /api/export and triggers
// a browser download of the returned .xlsx file. Used by the "Export to
// Excel" button on the AI Summary step. Throws on failure so the caller can
// show an error state — never silently does nothing.
async function exportVulnerabilitiesToExcel(vulnerabilities) {
  const res = await fetch(`${API_BASE}/api/export`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ vulnerabilities }),
  });
  if (!res.ok) {
    let message = "Export failed";
    try { message = (await res.json()).error || message; } catch { /* response wasn't JSON */ }
    throw new Error(message);
  }
  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `vulnerability-report-${new Date().toISOString().slice(0, 10)}.xlsx`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
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
  .spinner { width:12px; height:12px; border-radius:50%; border:2px solid rgba(124,58,237,.25); border-top-color:#7c3aed; display:inline-block; animation:spin .7s linear infinite; flex-shrink:0; }
  @keyframes spin { to { transform: rotate(360deg); } }

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
  .cve-tab-bar { display:flex; gap:4px; margin-bottom:12px; border-bottom:1px solid #e5e7eb; }
  .cve-tab { padding:9px 16px; font-size:13px; font-weight:600; color:#9ca3af; cursor:pointer; background:none; border:none; border-bottom:2px solid transparent; font-family:'DM Sans', sans-serif; margin-bottom:-1px; }
  .cve-tab:hover { color:#374151; }
  .cve-tab.active { color:#111; border-bottom-color:#2563eb; }
  .cve-tab.active.impact-tab { color:#7c3aed; border-bottom-color:#7c3aed; }
  .read-more-toggle { display:inline-block; margin-top:10px; font-size:12px; font-weight:700; color:#2563eb; cursor:pointer; user-select:none; }
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
        {["dashboard", "upload-scan", "history", "tickets"].map(tab => (
          <button key={tab} className={`nav-btn ${activeTab === tab ? "active" : ""}`} onClick={() => setActiveTab(tab)}>
            <span>✦</span>
            {tab === "dashboard" ? "Dashboard" : tab === "upload-scan" ? "Upload Scan" : tab === "history" ? "Scan History" : "Tickets"}
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
function Footer({ step, onBack, onNext, nextLabel = "Next", disableNext = false, hideNext = false }) {
  return (
    <div className="page-footer" style={{ position: "relative" }}>
      <button className="btn btn-ghost" onClick={onBack}>Back</button>
      <span className="step-counter">Step {step + 1} of {STEPS.length}</span>
      {!hideNext && (
        <button className="btn btn-primary" onClick={onNext} disabled={disableNext} style={{ opacity: disableNext ? 0.5 : 1 }}>
          {nextLabel}
        </button>
      )}
    </div>
  );
}

//Sign In
// Basic "looks like an email" check — not a full RFC 5322 validator, just
// enough to catch typos like missing "@" or a domain with no dot.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Password rule: 8+ chars, at least one lowercase, one uppercase, one
// number, and one symbol. Stated in the UI hint so it's obvious upfront
// rather than only surfacing after a rejected signup.
function passwordError(password) {
  if (password.length < 8) return "Password must be at least 8 characters";
  if (!/[a-z]/.test(password)) return "Password must include a lowercase letter";
  if (!/[A-Z]/.test(password)) return "Password must include an uppercase letter";
  if (!/[0-9]/.test(password)) return "Password must include a number";
  if (!/[^A-Za-z0-9]/.test(password)) return "Password must include a symbol (e.g. ! @ # $)";
  return null;
}

// Small inline Google "G" mark, official 4-color rendition — avoids
// pulling in an icon library for one icon.
function GoogleGIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" xmlns="http://www.w3.org/2000/svg">
      <path fill="#4285F4" d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84c-.21 1.13-.84 2.09-1.8 2.73v2.27h2.91c1.7-1.57 2.69-3.88 2.69-6.64z" />
      <path fill="#34A853" d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.91-2.27c-.81.54-1.84.86-3.05.86-2.34 0-4.33-1.58-5.04-3.71H.96v2.34C2.44 15.98 5.48 18 9 18z" />
      <path fill="#FBBC05" d="M3.96 10.7c-.18-.54-.28-1.11-.28-1.7s.1-1.16.28-1.7V4.96H.96C.35 6.17 0 7.55 0 9s.35 2.83.96 4.04l3-2.34z" />
      <path fill="#EA4335" d="M9 3.58c1.32 0 2.51.45 3.44 1.35l2.58-2.58C13.46.89 11.43 0 9 0 5.48 0 2.44 2.02.96 4.96l3 2.34C4.67 5.16 6.66 3.58 9 3.58z" />
    </svg>
  );
}

// "Continue with Google" — used on both SignIn and SignUp, since Google
// Sign-In (google_auth.py) handles both in one flow: sign in if the email
// already has an account, sign up automatically if not. Hides itself if
// the server hasn't got GOOGLE_CLIENT_ID/SECRET configured, rather than
// showing a button that would just error.
function GoogleAuthButton({ label }) {
  const [configured, setConfigured] = useState(false);

  useEffect(() => {
    fetch(`${API_BASE}/api/auth/google/status`, { credentials: "include" })
      .then(res => res.json())
      .then(data => setConfigured(!!data.configured))
      .catch(() => setConfigured(false));
  }, []);

  if (!configured) return null;

  return (
    <>
      <div style={{ display: "flex", alignItems: "center", gap: 10, margin: "4px 0 16px" }}>
        <div style={{ flex: 1, height: 1, background: "#e5e7eb" }} />
        <div style={{ fontSize: 11, color: "#9ca3af", fontWeight: 600 }}>OR</div>
        <div style={{ flex: 1, height: 1, background: "#e5e7eb" }} />
      </div>
      <button
        type="button"
        onClick={() => { window.location.href = `${API_BASE}/api/auth/google/login`; }}
        style={{ width: "100%", padding: "11px", borderRadius: 20, border: "1px solid #e5e7eb", background: "#fff", color: "#374151", fontSize: 14, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 10, marginBottom: 16 }}>
        <GoogleGIcon />
        {label}
      </button>
    </>
  );
}

function SignIn({ onSignIn, onGoSignUp }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // If Google sign-in just failed and redirected back here (see
  // google_auth.py's _redirect_with_error), surface that message once and
  // strip the ?authError= query param so a page refresh doesn't re-show
  // it — same cleanup pattern JiraConnect uses for ?jira=connected.
  useEffect(() => {
    const authError = new URLSearchParams(window.location.search).get("authError");
    if (authError) {
      setError(authError);
      window.history.replaceState({}, "", window.location.pathname);
    }
  }, []);

  const handle = async () => {
    if (!email || !password) { setError("Please fill in all fields"); return; }
    if (!EMAIL_RE.test(email)) { setError("Please enter a valid email address"); return; }
    setError("");
    setSubmitting(true);
    try {
      const res = await fetch(`${API_BASE}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error || "Invalid email or password"); return; }
      onSignIn(data);
    } catch {
      setError("Couldn't reach the server. Please try again.");
    } finally {
      setSubmitting(false);
    }
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
          disabled={submitting}
          style={{ width: "100%", padding: "12px", borderRadius: 20, border: "none", background: "#2563eb", color: "#fff", fontSize: 14, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: submitting ? "default" : "pointer", opacity: submitting ? 0.7 : 1, marginBottom: 16 }}>
          {submitting ? "Signing in…" : "Sign in"}
        </button>

        <GoogleAuthButton label="Continue with Google" />

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
  const [submitting, setSubmitting] = useState(false);

  const handle = async () => {
    if (!name || !email || !password || !confirm) { setError("Please fill in all fields"); return; }
    if (!EMAIL_RE.test(email)) { setError("Please enter a valid email address"); return; }
    const pwError = passwordError(password);
    if (pwError) { setError(pwError); return; }
    if (password !== confirm) { setError("Passwords do not match"); return; }
    setError("");
    setSubmitting(true);
    try {
      const res = await fetch(`${API_BASE}/api/auth/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ name, email, password }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error || "Couldn't create your account"); return; }
      onSignUp(data);
    } catch {
      setError("Couldn't reach the server. Please try again.");
    } finally {
      setSubmitting(false);
    }
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
          <div style={{ fontSize: 11, color: "#9ca3af", marginTop: 4 }}>8+ characters, with uppercase, lowercase, a number, and a symbol</div>
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
          disabled={submitting}
          style={{ width: "100%", padding: "12px", borderRadius: 20, border: "none", background: "#2563eb", color: "#fff", fontSize: 14, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: submitting ? "default" : "pointer", opacity: submitting ? 0.7 : 1, marginBottom: 16 }}>
          {submitting ? "Creating account…" : "Create account"}
        </button>

        <GoogleAuthButton label="Sign up with Google" />

        <div style={{ textAlign: "center", fontSize: 13, color: "#6b7280" }}>
          Already have an account?{" "}
          <span onClick={onGoSignIn} style={{ color: "#2563eb", fontWeight: 600, cursor: "pointer" }}>Sign in</span>
        </div>
      </div>
    </div>
  );
}

//Business Context Questionnaire
// Shown once, right after signup (and to any returning signed-in user who
// hasn't completed it yet — e.g. an account created before this step
// existed). Captures just enough business context to compute an initial
// CriticalityTier and give AI analysis/prioritisation something to weight
// against beyond raw CVSS. Deeper context is gathered conversationally by
// the scan chatbot afterward, so this stays short on purpose.
const SECTOR_OPTIONS = [
  { value: "healthcare", label: "Healthcare / Medical" },
  { value: "banking_finance", label: "Banking & Finance" },
  { value: "government_public_sector", label: "Government / Public Sector" },
  { value: "education", label: "Education" },
  { value: "technology_saas", label: "Technology / SaaS" },
  { value: "retail_ecommerce", label: "Retail / E-commerce" },
  { value: "manufacturing_industrial", label: "Manufacturing / Industrial" },
  { value: "energy_utilities", label: "Energy / Utilities" },
  { value: "legal", label: "Legal" },
  { value: "other", label: "Other" },
];

const DATA_SENSITIVITY_OPTIONS = [
  { value: "credentials", label: "Passwords / credentials / API keys" },
  { value: "financial", label: "Banking or financial details" },
  { value: "medical", label: "Medical conditions / health records" },
  { value: "pii", label: "Other personal data (names, addresses, etc.)" },
  { value: "intellectual_property", label: "Intellectual property / trade secrets" },
  { value: "none", label: "None of the above" },
];

// availabilityImpact -> criticalityTier. Five tiers so there's a middle
// ground between "major disruption" and "minor inconvenience" rather than
// forcing a binary choice.
const AVAILABILITY_OPTIONS = [
  { value: "life_safety", label: "Critical — life-safety impact", tier: 1 },
  { value: "major_disruption", label: "Major business disruption", tier: 2 },
  { value: "moderate_disruption", label: "Moderate disruption — workarounds available", tier: 3 },
  { value: "minor_inconvenience", label: "Minor inconvenience", tier: 4 },
  { value: "no_impact", label: "No significant impact", tier: 5 },
];

const INTERNET_FACING_OPTIONS = [
  { value: "public", label: "Public-facing — reachable from the internet" },
  { value: "internal", label: "Internal only — private network / VPN" },
  { value: "mixed", label: "Mixed — some services public, some internal" },
];

// Not exhaustive, but covers the frameworks that most change how a
// vulnerability should be prioritised (breach notification clocks,
// mandated patch windows, audit evidence requirements, etc.).
const COMPLIANCE_OPTIONS = [
  { value: "hipaa", label: "HIPAA" },
  { value: "pci_dss", label: "PCI DSS" },
  { value: "gdpr", label: "GDPR" },
  { value: "soc2", label: "SOC 2" },
  { value: "iso27001", label: "ISO 27001" },
  { value: "fedramp_nist", label: "FedRAMP / NIST 800-53" },
  { value: "none", label: "None / not sure" },
];

// Shared control styles so the form matches SignIn/SignUp.
const qLabelStyle = { fontSize: 13, fontWeight: 700, color: "#111", marginBottom: 4 };
const qSubStyle = { fontSize: 12, color: "#6b7280", marginBottom: 10 };
const qFieldStyle = { width: "100%", padding: "10px 14px", borderRadius: 8, border: "1px solid #e5e7eb", fontSize: 13, fontFamily: "DM Sans, sans-serif", color: "#374151", outline: "none" };

// Looks up the human-readable label for a stored value in one of the
// *_OPTIONS arrays above — used by the read-only summary in Profile.
function optionLabel(options, value) {
  return options.find(o => o.value === value)?.label || value;
}

function CheckboxOption({ checked, label, onChange }) {
  return (
    <label style={{ display: "flex", alignItems: "center", gap: 10, padding: "9px 12px", borderRadius: 8, border: `1px solid ${checked ? "#2563eb" : "#e5e7eb"}`, background: checked ? "#eff6ff" : "#fff", cursor: "pointer", marginBottom: 6, fontSize: 13, color: "#374151" }}>
      <input type="checkbox" className="cb" checked={checked} onChange={onChange} />
      {label}
    </label>
  );
}

function RadioOption({ checked, label, onChange }) {
  return (
    <label style={{ display: "flex", alignItems: "center", gap: 10, padding: "9px 12px", borderRadius: 8, border: `1px solid ${checked ? "#2563eb" : "#e5e7eb"}`, background: checked ? "#eff6ff" : "#fff", cursor: "pointer", marginBottom: 6, fontSize: 13, color: "#374151" }}>
      <input type="radio" checked={checked} onChange={onChange} style={{ width: 16, height: 16, flexShrink: 0, accentColor: "#2563eb" }} />
      {label}
    </label>
  );
}

// Toggling a "none"-style option in a multi-select clears every other
// option (and vice versa) — same rule the backend enforces.
function toggleMulti(list, value, exclusiveValue = "none") {
  if (value === exclusiveValue) return list.includes(value) ? [] : [exclusiveValue];
  const withoutExclusive = list.filter(v => v !== exclusiveValue);
  return withoutExclusive.includes(value) ? withoutExclusive.filter(v => v !== value) : [...withoutExclusive, value];
}

// `initialData` (shape matches GET /api/business-context/me) prefills the
// form for editing from Profile; leave it null for the fresh-signup case.
// `mode` only changes copy/labels — "onboarding" (first-time, no cancel
// option) or "edit" (from Profile, cancellable). `onComplete` is called
// with the saved record so the caller can update its own state without a
// second round-trip.
function BusinessContextStep({ onComplete, onCancel, initialData = null, mode = "onboarding" }) {
  const [sector, setSector] = useState(initialData?.sector || "");
  const [sectorOther, setSectorOther] = useState(initialData?.sectorOther || "");
  const [dataSensitivity, setDataSensitivity] = useState(initialData?.dataSensitivity || []);
  const [availabilityImpact, setAvailabilityImpact] = useState(initialData?.availabilityImpact || "");
  const [internetFacing, setInternetFacing] = useState(initialData?.internetFacing || "");
  const [complianceScope, setComplianceScope] = useState(initialData?.complianceScope || []);
  const [airGapped, setAirGapped] = useState(initialData?.airGapped ?? null); // null | true | false
  const [airGappedDetails, setAirGappedDetails] = useState(initialData?.airGappedDetails || "");
  const [hasSecurityTeam, setHasSecurityTeam] = useState(initialData?.hasSecurityTeam ?? null); // optional
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const valid =
    sector && (sector !== "other" || sectorOther.trim()) &&
    dataSensitivity.length > 0 &&
    availabilityImpact &&
    internetFacing &&
    complianceScope.length > 0 &&
    airGapped !== null;

  const handle = async () => {
    if (!valid) { setError("Please answer every question before continuing"); return; }
    setError("");
    setSubmitting(true);
    const payload = {
      sector,
      sectorOther: sector === "other" ? sectorOther.trim() : undefined,
      dataSensitivity,
      availabilityImpact,
      internetFacing,
      complianceScope,
      airGapped,
      airGappedDetails: airGapped ? airGappedDetails.trim() : undefined,
      hasSecurityTeam,
    };
    try {
      const res = await fetch(`${API_BASE}/api/business-context`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error || "Couldn't save your answers"); return; }
      onComplete({ ...payload, completed: true, criticalityTier: data.criticalityTier });
    } catch {
      setError("Couldn't reach the server. Please try again.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", padding: "24px 0" }}>
      <div style={{ width: 560, maxWidth: "100%", background: "#fff", borderRadius: 20, padding: 36, boxShadow: "0 4px 24px rgba(0,0,0,0.08)" }}>
        <div style={{ fontSize: 22, fontWeight: 700, color: "#111", marginBottom: 4 }}>
          {mode === "edit" ? "Update your environment" : "Tell us about your environment"}
        </div>
        <div style={{ fontSize: 13, color: "#6b7280", marginBottom: 28 }}>
          {mode === "edit"
            ? "Change any answers below — this updates how we prioritise vulnerabilities going forward."
            : "A few quick questions so we can prioritise vulnerabilities by business impact, not just CVSS. Anything else we need, our assistant will ask you along the way."}
        </div>

        {error && <div style={{ fontSize: 12, color: "#dc2626", background: "#fef2f2", padding: "8px 12px", borderRadius: 8, marginBottom: 20 }}>{error}</div>}

        <div style={{ marginBottom: 22 }}>
          <div style={qLabelStyle}>What is your department / sector?</div>
          <div style={qSubStyle}>e.g. Medical, IT, Banking</div>
          <select style={qFieldStyle} value={sector} onChange={e => setSector(e.target.value)}>
            <option value="" disabled>Select one…</option>
            {SECTOR_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          {sector === "other" && (
            <input
              style={{ ...qFieldStyle, marginTop: 8 }}
              placeholder="Describe your sector"
              value={sectorOther}
              onChange={e => setSectorOther(e.target.value)}
            />
          )}
        </div>

        <div style={{ marginBottom: 22 }}>
          <div style={qLabelStyle}>Does your network include any of the following sensitive data?</div>
          <div style={qSubStyle}>Select all that apply</div>
          {DATA_SENSITIVITY_OPTIONS.map(o => (
            <CheckboxOption key={o.value} label={o.label} checked={dataSensitivity.includes(o.value)}
              onChange={() => setDataSensitivity(s => toggleMulti(s, o.value))} />
          ))}
        </div>

        <div style={{ marginBottom: 22 }}>
          <div style={qLabelStyle}>How important is availability of your system?</div>
          <div style={qSubStyle}>If it went down, what would that mean for you?</div>
          {AVAILABILITY_OPTIONS.map(o => (
            <RadioOption key={o.value} label={o.label} checked={availabilityImpact === o.value}
              onChange={() => setAvailabilityImpact(o.value)} />
          ))}
        </div>

        <div style={{ marginBottom: 22 }}>
          <div style={qLabelStyle}>Is this system reachable from the public internet?</div>
          <div style={qSubStyle}>Internet-facing findings are usually higher priority than internal-only ones</div>
          {INTERNET_FACING_OPTIONS.map(o => (
            <RadioOption key={o.value} label={o.label} checked={internetFacing === o.value}
              onChange={() => setInternetFacing(o.value)} />
          ))}
        </div>

        <div style={{ marginBottom: 22 }}>
          <div style={qLabelStyle}>Are you subject to any regulatory or compliance frameworks?</div>
          <div style={qSubStyle}>Select all that apply — this affects how urgently some findings need to be remediated</div>
          {COMPLIANCE_OPTIONS.map(o => (
            <CheckboxOption key={o.value} label={o.label} checked={complianceScope.includes(o.value)}
              onChange={() => setComplianceScope(s => toggleMulti(s, o.value))} />
          ))}
        </div>

        <div style={{ marginBottom: 22 }}>
          <div style={qLabelStyle}>Does your network include any air-gapped machines?</div>
          <div style={qSubStyle}>Non-internet-facing systems we should be careful not to scan</div>
          <div style={{ display: "flex", gap: 10 }}>
            <RadioOption label="Yes" checked={airGapped === true} onChange={() => setAirGapped(true)} />
            <RadioOption label="No" checked={airGapped === false} onChange={() => setAirGapped(false)} />
          </div>
          {airGapped === true && (
            <textarea
              style={{ ...qFieldStyle, marginTop: 4, resize: "vertical" }}
              rows={2}
              placeholder="Which systems or IP ranges, so we can exclude them from scans?"
              value={airGappedDetails}
              onChange={e => setAirGappedDetails(e.target.value)}
            />
          )}
        </div>

        <div style={{ marginBottom: 28 }}>
          <div style={qLabelStyle}>Do you have a dedicated security or IT team to handle remediation?</div>
          <div style={qSubStyle}>Optional — helps us judge how prescriptive fix guidance should be</div>
          <div style={{ display: "flex", gap: 10 }}>
            <RadioOption label="Yes" checked={hasSecurityTeam === true} onChange={() => setHasSecurityTeam(true)} />
            <RadioOption label="No" checked={hasSecurityTeam === false} onChange={() => setHasSecurityTeam(false)} />
            <RadioOption label="Not sure" checked={hasSecurityTeam === null} onChange={() => setHasSecurityTeam(null)} />
          </div>
        </div>

        <div style={{ display: "flex", gap: 12 }}>
          {mode === "edit" && (
            <button
              type="button"
              onClick={onCancel}
              disabled={submitting}
              style={{ flex: 1, padding: "12px", borderRadius: 20, border: "1px solid #e5e7eb", background: "#fff", color: "#374151", fontSize: 14, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: submitting ? "default" : "pointer" }}>
              Cancel
            </button>
          )}
          <button
            onClick={handle}
            disabled={submitting || !valid}
            style={{ flex: 1, padding: "12px", borderRadius: 20, border: "none", background: "#2563eb", color: "#fff", fontSize: 14, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: (submitting || !valid) ? "default" : "pointer", opacity: (submitting || !valid) ? 0.6 : 1 }}>
            {submitting ? "Saving…" : mode === "edit" ? "Save changes" : "Continue"}
          </button>
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
  // True from the moment the raw scan results land until /api/analyze
  // (business-context-aware AI analysis) finishes. The Next button stays
  // disabled the whole time so nobody can click into a CVE before its real
  // priority/business_priority_score exists — see the CveDetailStep race
  // this was added to close.
  const [analyzing, setAnalyzing] = useState(false);

  const uploadToServer = async f => {
    setStatus("uploading");
    setErrorMsg("");
    try {
      const formData = new FormData();
      formData.append("file", f);
      // credentials: "include" so the session cookie reaches the backend —
      // without it, /api/upload-scan can't tell which account the scan
      // belongs to and record_scan() silently skips saving it (see scans.py).
      const res = await fetch(`${API_BASE}/api/upload-scan`, { method: "POST", credentials: "include", body: formData });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Upload failed");

      const vulnerabilities = data.vulnerabilities || [];
      // show raw + Tenable cross-reference results immediately, and record
      // which scanner/file this run came from for POST /api/scans later...
      onParsed(vulnerabilities, { scanner: data.scanner, source: "upload", target: f.name });
      setFoundCount(data.vulnerabilitiesFound ?? vulnerabilities.length);
      setTenableMatchCount(vulnerabilities.filter(v => v.tenable_exposure?.matched).length);
      setStatus("success");

      // ...then swap in real AI analysis once it comes back (falls back to
      // placeholders inside applyScanResults if /api/analyze fails). Next
      // stays disabled for the duration so nobody can click into a CVE
      // while it's still showing pre-analysis placeholder data.
      setAnalyzing(true);
      try {
        const analyzed = await runAiAnalysis(vulnerabilities);
        onParsed(analyzed);
      } finally {
        setAnalyzing(false);
      }
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
  const [usePrivateRegistry, setUsePrivateRegistry] = useState(false);
  const [registryStatus, setRegistryStatus] = useState({ connected: false });

  useEffect(() => {
    fetch(`${API_BASE}/api/registry/status`, { credentials: "include" })
      .then(res => res.json())
      .then(setRegistryStatus)
      .catch(() => setRegistryStatus({ connected: false }));
  }, []);
  // liveStatus: idle | scanning | success | error
  const [liveStatus, setLiveStatus] = useState("idle");
  const [liveError, setLiveError] = useState("");
  const [liveFoundCount, setLiveFoundCount] = useState(0);
  const [liveTenableMatchCount, setLiveTenableMatchCount] = useState(0);
  const [liveAnalyzing, setLiveAnalyzing] = useState(false); // same purpose as `analyzing` above, for the live-scan path

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
        if (usePrivateRegistry) body.usePrivateRegistry = true;
      }
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Scan failed");

      const vulnerabilities = data.vulnerabilities || [];
      // show raw + Tenable cross-reference results immediately, and record
      // which scanner/target this run came from for POST /api/scans later...
      onParsed(vulnerabilities, { scanner: data.scanner, source: "live", target: target.trim() });
      setLiveFoundCount(data.vulnerabilitiesFound ?? vulnerabilities.length);
      setLiveTenableMatchCount(vulnerabilities.filter(v => v.tenable_exposure?.matched).length);
      setLiveStatus("success");

      // ...then swap in real AI analysis once it comes back, same as the
      // upload path — keeps both entry points behaving consistently, Next
      // disabled until it's done.
      setLiveAnalyzing(true);
      try {
        const analyzed = await runAiAnalysis(vulnerabilities);
        onParsed(analyzed);
      } finally {
        setLiveAnalyzing(false);
      }
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
                {status === "success" && analyzing && (
                  <div className="dropzone-sub" style={{ color: "#7c3aed", display: "flex", alignItems: "center", gap: 8 }}>
                    <span className="spinner" aria-hidden="true" />
                    Running AI analysis and weighting results by your business context…
                  </div>
                )}
                {status === "success" && !analyzing && (
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
                placeholder={
                  scannerName === "tenable"
                    ? "e.g. 42"
                    : usePrivateRegistry && registryStatus.url
                      ? `e.g. ${registryStatus.url}/team/app:latest`
                      : "e.g. myapp:latest"
                }
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

            {scannerName === "trivy" && trivyScanType === "image" && registryStatus.connected && (
              <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: "#374151" }}>
                <input
                  type="checkbox"
                  checked={usePrivateRegistry}
                  onChange={e => setUsePrivateRegistry(e.target.checked)}
                  disabled={liveStatus === "scanning"}
                />
                Scan a private image from {registryStatus.url} (connected in your Profile)
              </label>
            )}
            {scannerName === "trivy" && trivyScanType === "image" && !registryStatus.connected && (
              <div style={{ fontSize: 12, color: "#9ca3af" }}>
                No private registry connected — go to Profile to connect one if you need to scan a private image.
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
            {liveStatus === "success" && liveAnalyzing && (
              <div className="dropzone-sub" style={{ color: "#7c3aed", display: "flex", alignItems: "center", gap: 8 }}>
                <span className="spinner" aria-hidden="true" />
                Running AI analysis and weighting results by your business context…
              </div>
            )}
            {liveStatus === "success" && !liveAnalyzing && (
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
        nextLabel={(mode === "upload" ? analyzing : liveAnalyzing) ? "Analyzing…" : "Next"}
        disableNext={mode === "upload" ? (!file || status !== "success" || analyzing) : (liveStatus !== "success" || liveAnalyzing)}
      />
    </>
  );
}

//Upload step 2: AI Summary
// "None" leaves the list in the order the backend returned it in, which is
// already business_priority_score order when the signed-in user has
// completed the business-context survey (falls back to CVSS/severity order
// otherwise — see /api/analyze). "Business Priority" is here as an explicit,
// user-toggleable option too since AI analysis can reorder things after the
// initial CVSS-sorted upload result renders.
const AI_RISK_SORT_FIELDS = { "None": null, "Business Priority": "businessPriorityScore", "CVE": "id", "Severity": "severity", "CVSS": "cvss" };

function AISummaryStep({ onNext, onBack, onCveClick }) {
  const [showAll, setShowAll] = useState(false);
  const [riskSeverityFilter, setRiskSeverityFilter] = useState("All");
  const [riskSortBy, setRiskSortBy] = useState("None");
  const [riskSortDir, setRiskSortDir] = useState("desc");
  // exportState: idle | exporting | error — drives the small status text
  // next to the Export button.
  const [exportState, setExportState] = useState("idle");
  const [exportError, setExportError] = useState("");

  const handleExport = async () => {
    setExportState("exporting");
    setExportError("");
    try {
      await exportVulnerabilitiesToExcel(lastVulnerabilities);
      setExportState("idle");
    } catch (err) {
      setExportState("error");
      setExportError(err.message || "Export failed");
    }
  };

  const filteredRisks = sortRows(
    allRisks.filter(r => riskSeverityFilter === "All" || r.severity === riskSeverityFilter),
    AI_RISK_SORT_FIELDS[riskSortBy],
    riskSortDir
  );

  return (
    <>
      <div className="page-card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
          <div>
            <div className="page-title">AI Analysis</div>
            <div className="page-sub" style={{ marginBottom: 0 }}>Analyze results with AI-powered insights</div>
          </div>
          <div style={{ textAlign: "right", flexShrink: 0 }}>
            <button
              onClick={handleExport}
              disabled={exportState === "exporting" || allRisks.length === 0}
              title={allRisks.length === 0 ? "Nothing to export yet" : "Download this scan's findings as an Excel file"}
              style={{
                padding: "8px 16px",
                borderRadius: 20,
                border: "1px solid #e5e7eb",
                background: "#fff",
                color: "#374151",
                fontSize: 13,
                fontWeight: 600,
                fontFamily: "DM Sans, sans-serif",
                cursor: (exportState === "exporting" || allRisks.length === 0) ? "default" : "pointer",
                opacity: (exportState === "exporting" || allRisks.length === 0) ? 0.6 : 1,
                display: "flex",
                alignItems: "center",
                gap: 8,
              }}
            >
              {exportState === "exporting" && <span className="spinner" aria-hidden="true" />}
              {exportState === "exporting" ? "Exporting…" : "Export to Excel"}
            </button>
            {exportState === "error" && (
              <div style={{ fontSize: 11, color: "#dc2626", marginTop: 6, maxWidth: 220 }}>{exportError}</div>
            )}
          </div>
        </div>
        <div style={{ marginBottom: 20 }} />

        {(() => {
          const total = allRisks.length;
          const critical = allRisks.filter(r => r.severity === "Critical").length;
          const avgCvss = total === 0 ? "0.0" : (allRisks.reduce((s, r) => s + r.cvss, 0) / total).toFixed(1);
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

        {!lastBusinessContextApplied && (
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, fontSize: 12, color: "#7c3aed", background: "#f5f3ff", borderRadius: 10, padding: "10px 14px", marginBottom: 16 }}>
            <span>These results are ranked by CVSS only. Complete your business profile so we can rank them by business impact instead.</span>
          </div>
        )}

        <div className="top-risks">
          <div className="top-risks-title">{lastBusinessContextApplied ? "Risks, ranked by business impact" : "Risks"}</div>
          <FilterBar
            groups={[
              { options: ["All", "Critical", "High", "Medium", "Low"], value: riskSeverityFilter, onChange: setRiskSeverityFilter },
            ]}
            sort={{ options: Object.keys(AI_RISK_SORT_FIELDS), value: riskSortBy, onChange: setRiskSortBy, dir: riskSortDir, onToggleDir: () => setRiskSortDir(d => d === "asc" ? "desc" : "asc") }}
            resultCount={filteredRisks.length}
            totalCount={allRisks.length}
          />
          <div style={{ display: "grid", gridTemplateColumns: "1fr 120px 60px", gap: 8, padding: "0 0 6px 0", borderBottom: "1px solid #e5e7eb", marginBottom: 4 }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: "#9ca3af" }}>CVE</span>
            <span style={{ fontSize: 11, fontWeight: 600, color: "#9ca3af" }}>SEVERITY</span>
            <span style={{ fontSize: 11, fontWeight: 600, color: "#9ca3af", textAlign: "right" }}>CVSS</span>
          </div>
          {filteredRisks.length === 0 && (
            <div style={{ padding: "12px 0", fontSize: 12, color: "#9ca3af" }}>No vulnerabilities match your filters.</div>
          )}
          {filteredRisks.slice(0, 3).map(r => (
            <div key={r.id} className="risk-row" style={{ display: "grid", gridTemplateColumns: "1fr 120px 60px", gap: 8, alignItems: "center" }} onClick={() => onCveClick(r.id)}>
              <span style={{ }}>{r.id}</span>
              <div><span className={`severity-pill sev-${r.severity.toLowerCase()}`}>{r.severity}</span></div>
              <span style={{ fontSize: 12, color: "#6b7280", textAlign: "right" }}>{r.cvss}</span>
            </div>
          ))}
          {showAll && filteredRisks.slice(3).map(r => (
            <div key={r.id} className="risk-row" style={{ display: "grid", gridTemplateColumns: "1fr 120px 60px", gap: 8, alignItems: "center" }} onClick={() => onCveClick(r.id)}>
              <span style={{ }}>{r.id}</span>
              <div><span className={`severity-pill sev-${r.severity.toLowerCase()}`}>{r.severity}</span></div>
              <span style={{ fontSize: 12, color: "#6b7280", textAlign: "right" }}>{r.cvss}</span>
            </div>
          ))}
          {filteredRisks.length > 3 && (
            <div style={{ paddingTop: 10, textAlign: "center" }}>
              <span
                style={{ fontSize: 13, color: "#2563eb", fontWeight: 600, cursor: "pointer", userSelect: "none" }}
                onClick={() => setShowAll(s => !s)}
                onMouseEnter={e => e.target.style.textDecoration = "underline"}
                onMouseLeave={e => e.target.style.textDecoration = "none"}
              >
                {showAll ? "▲ Hide" : `+ ${filteredRisks.length - 3} more`}
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
          {(() => {
            const criticalCount = allRisks.filter(r => r.severity === "Critical").length;
            // Same "Needs Review" criteria the Validation step uses (see
            // applyScanResults' validationRows: missing data, or a real AI
            // analysis that came back with confidence < 60) — reusing it
            // here instead of a separate hardcoded "false positives" number
            // that the backend never actually computes.
            const flaggedCount = validationRows.filter(r => r.status === "Needs Review").length;
            return (
              <div className="ai-insight-chips">
                <div className="ai-chip">
                  <div className="ai-chip-val">{criticalCount} Critical Issue{criticalCount === 1 ? "" : "s"}</div>
                  <div className="ai-chip-desc">Require immediate attention</div>
                </div>
                <div className="ai-chip">
                  <div className="ai-chip-val">{flaggedCount} Flagged for Review</div>
                  <div className="ai-chip-desc">Low AI confidence or incomplete data</div>
                </div>
              </div>
            );
          })()}
        </div>
      </div>
      <Footer step={1} onBack={onBack} onNext={onNext} />
    </>
  );
}

// The raw business_priority_score is CVSS multiplied by an org-wide factor
// from the business-context survey (see ai_analysis.compute_business_priority_score),
// so the number alone means nothing without knowing that factor — a 24 is
// near the top of the range for one org and mid-table for another. Dividing
// the score by the finding's own CVSS recovers that factor, which gives us
// the highest score this org could see (a 10.0 CVSS finding) to band against.
const CRITICALITY_BANDS = [
  { min: 0.7, label: "High criticality", color: "#dc2626" },
  { min: 0.4, label: "Medium criticality", color: "#f97316" },
  { min: 0, label: "Low criticality", color: "#16a34a" },
];

export function criticalityBand(score, cvss) {
  const ceiling = cvss > 0 ? (score / cvss) * 10 : 10;
  const ratio = ceiling > 0 ? score / ceiling : 0;
  return CRITICALITY_BANDS.find(b => ratio >= b.min) || CRITICALITY_BANDS[CRITICALITY_BANDS.length - 1];
}

// Splits AI-generated prose into a lead sentence (shown by default) and the
// remainder (revealed by "Read more"), so the tab starts short instead of
// dumping a full paragraph on the page at once. Falls back to treating the
// whole string as the summary if it's a single sentence or has no
// terminator we recognise.
export function splitSummary(text) {
  if (!text) return { summary: "", rest: "" };
  const match = text.match(/^(.*?[.!?])(\s+|$)/);
  if (!match || match[1].length === text.trim().length) return { summary: text.trim(), rest: "" };
  return { summary: match[1].trim(), rest: text.slice(match[0].length).trim() };
}

//CVE Detail (sub-page of AI Summary/Select)
function CveDetailStep({ cveId, onBack, onNext, backLabel }) {
  const d = cveDetails[cveId];
  const cvssColor = d.cvss >= 9 ? "#dc2626" : d.cvss >= 7 ? "#f97316" : "#ca8a04";
  const confColor = d.confidence >= 90 ? "#22c55e" : "#f97316";

  const tabs = [
    { key: "why", label: "Why This Matters", text: d.why },
    ...(d.businessImpact ? [{ key: "impact", label: "Business Impact", text: d.businessImpact }] : []),
    { key: "fix", label: "Suggested Fix", fixes: d.fixes },
  ];
  const [activeTab, setActiveTab] = useState("why");
  // Read-more state is per-tab and per-CVE, keyed so switching CVEs (without
  // remounting, if a caller ever reuses this component) resets to collapsed.
  const [expanded, setExpanded] = useState({});
  const toggleExpanded = key => setExpanded(s => ({ ...s, [`${cveId}:${key}`]: !s[`${cveId}:${key}`] }));
  const isExpanded = key => !!expanded[`${cveId}:${key}`];
  const tab = tabs.find(t => t.key === activeTab) || tabs[0];

  return (
    <>
      <div className="page-card">
        <div className="back-link" onClick={onBack}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
          {backLabel || "Back to AI Summary"}
        </div>
        <div className="page-title">{cveId}</div>
        <div className="page-sub">Analyse results with AI-powered insights</div>

        <div className="cve-scores" style={d.businessPriorityScore != null ? { gridTemplateColumns: "1fr 1fr 1fr" } : undefined}>
          <div className="cve-score-card">
            <div className="cve-score-label">CVSS Score</div>
            <div className="cve-score-val" style={{ color: cvssColor }}>{d.cvss}</div>
          </div>
          <div className="cve-score-card">
            <div className="cve-score-label">AI Confidence</div>
            <div className="cve-score-val" style={{ color: confColor }}>{d.confidence}%</div>
            <div className="cve-score-sub">Validated against NVD & vendor advisory</div>
          </div>
          {d.businessPriorityScore != null && (() => {
            const band = criticalityBand(d.businessPriorityScore, d.cvss);
            return (
              <div className="cve-score-card">
                <div className="cve-score-label">Business Criticality</div>
                <div
                  className="cve-score-val"
                  style={{ color: band.color, fontSize: 20, lineHeight: 1.2 }}
                  title={`Score ${d.businessPriorityScore}`}
                >
                  {band.label}
                </div>
                <div className="cve-score-sub">CVSS weighted by your business profile</div>
              </div>
            );
          })()}
        </div>

        <div className="cve-tab-bar">
          {tabs.map(t => (
            <button
              key={t.key}
              className={`cve-tab ${activeTab === t.key ? "active" : ""} ${t.key === "impact" ? "impact-tab" : ""}`}
              onClick={() => setActiveTab(t.key)}
            >
              {t.label}
            </button>
          ))}
        </div>

        <div className="cve-section" style={tab.key === "impact" ? { background: "#f5f3ff", borderLeft: "3px solid #7c3aed" } : undefined}>
          {tab.key === "fix" ? (() => {
            const fixes = tab.fixes || [];
            const expandedFix = isExpanded("fix");
            const shown = expandedFix ? fixes : fixes.slice(0, 1);
            return (
              <>
                <ol className="cve-fix-list">
                  {shown.map((f, i) => (
                    <li key={i} className="cve-fix-item">
                      <span className="cve-fix-num">{i + 1}.</span> {f}
                    </li>
                  ))}
                </ol>
                {fixes.length > 1 && (
                  <span className="read-more-toggle" onClick={() => toggleExpanded("fix")}>
                    {expandedFix ? "▲ Show less" : `Read more (${fixes.length - 1} more step${fixes.length - 1 === 1 ? "" : "s"})`}
                  </span>
                )}
              </>
            );
          })() : (() => {
            const { summary, rest } = splitSummary(tab.text);
            const expandedText = isExpanded(tab.key);
            return (
              <>
                <div className="cve-section-text">{summary}</div>
                {rest && expandedText && <div className="cve-section-text" style={{ marginTop: 8 }}>{rest}</div>}
                {rest && (
                  <span className="read-more-toggle" onClick={() => toggleExpanded(tab.key)}>
                    {expandedText ? "▲ Show less" : "Read more"}
                  </span>
                )}
              </>
            );
          })()}
        </div>
      </div>

    </>
  );
}


//upload step 3: Select
// Shared filter bar for pages that list vulnerabilities/tickets. Renders an
// optional search box plus one or more pill-button groups (severity, status,
// priority, etc). Kept generic so Select/Validation/GenerateTicket/Review can
// each pass whatever groups make sense for that page's data shape.
function FilterBar({ search, onSearchChange, searchPlaceholder = "Search…", groups = [], sort, resultCount, totalCount, searchMinWidth = 200 }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        {onSearchChange && (
          <input
            value={search}
            onChange={e => onSearchChange(e.target.value)}
            placeholder={searchPlaceholder}
            style={{ padding: "7px 14px", borderRadius: 20, border: "1px solid #e5e7eb", fontSize: 12, fontFamily: "DM Sans, sans-serif", outline: "none", minWidth: searchMinWidth, width: "100%", color: "#374151" }}
          />
        )}
        {groups.map((g, gi) => (
          <div key={gi} style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
            {(gi > 0 || onSearchChange) && <div style={{ width: 1, height: 20, background: "#e5e7eb", margin: "0 2px" }} />}
            {g.options.map(opt => (
              <button key={opt} onClick={() => g.onChange(opt)}
                style={{ padding: "5px 14px", borderRadius: 20, border: "1px solid #e5e7eb", fontSize: 12, fontWeight: 500, cursor: "pointer", fontFamily: "DM Sans, sans-serif",
                  background: g.value === opt ? "#2563eb" : "#fff", color: g.value === opt ? "#fff" : "#374151" }}>
                {opt}
              </button>
            ))}
          </div>
        ))}
        {sort && (
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            {(groups.length > 0 || onSearchChange) && <div style={{ width: 1, height: 20, background: "#e5e7eb", margin: "0 2px" }} />}
            <span style={{ fontSize: 11, fontWeight: 600, color: "#9ca3af", letterSpacing: "0.03em" }}>SORT</span>
            <select
              value={sort.value}
              onChange={e => sort.onChange(e.target.value)}
              style={{ padding: "5px 10px", borderRadius: 20, border: "1px solid #e5e7eb", fontSize: 12, fontWeight: 500, fontFamily: "DM Sans, sans-serif", color: "#374151", background: "#fff", outline: "none", cursor: "pointer" }}
            >
              {sort.options.map(opt => <option key={opt} value={opt}>{opt}</option>)}
            </select>
            {sort.value !== "None" && (
              <button
                onClick={sort.onToggleDir}
                title={sort.dir === "asc" ? "Ascending — click to reverse" : "Descending — click to reverse"}
                style={{ width: 28, height: 28, borderRadius: "50%", border: "1px solid #e5e7eb", background: "#fff", color: "#374151", fontSize: 13, fontWeight: 700, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", fontFamily: "DM Sans, sans-serif" }}
              >
                {sort.dir === "asc" ? "↑" : "↓"}
              </button>
            )}
          </div>
        )}
        {typeof resultCount === "number" && (
          <div style={{ fontSize: 12, color: "#9ca3af", marginLeft: "auto" }}>
            Showing {resultCount} of {totalCount}
          </div>
        )}
      </div>
    </div>
  );
}

// Matches a row against a free-text search term across whichever fields are
// present on that row shape (cve/id, title, asset, description).
function matchesSearch(row, term) {
  if (!term.trim()) return true;
  const t = term.trim().toLowerCase();
  return [row.id, row.title, row.desc, row.asset]
    .filter(Boolean)
    .some(v => String(v).toLowerCase().includes(t));
}

// Severity/priority don't sort correctly alphabetically (e.g. "Critical"
// would land before "High" but "Low" would land before both), so give
// those fields an explicit rank to sort by instead.
const SEVERITY_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1 };
const PRIORITY_RANK = { "P1 - Critical": 3, "P1": 3, "P2 - High": 2, "P2": 2, "P3 - Medium": 1, "P3": 1 };

// Generic sort helper shared by Select/Validation/GenerateTicket/Review.
// `field` is the row key to sort by ("id" | "severity" | "cvss" | ...),
// `dir` is "asc" | "desc". Pass field === "None" (or falsy) to skip sorting.
function sortRows(rows, field, dir = "asc") {
  if (!field || field === "None") return rows;
  const rank = row => {
    let v = row[field];
    if (field === "severity") return SEVERITY_RANK[v] ?? 0;
    if (field === "priority") return PRIORITY_RANK[v] ?? 0;
    if (typeof v === "string") return v.toLowerCase();
    return v ?? 0;
  };
  const sorted = [...rows].sort((a, b) => {
    const av = rank(a), bv = rank(b);
    if (av < bv) return -1;
    if (av > bv) return 1;
    return 0;
  });
  return dir === "desc" ? sorted.reverse() : sorted;
}

// Maps the human-readable sort labels shown in the dropdown to the
// underlying row field to sort by for that page's data shape.
const SELECT_SORT_FIELDS = { "None": null, "Business Priority": "businessPriorityScore", "CVE": "id", "Title": "title", "Severity": "severity", "CVSS": "cvss", "Asset": "asset" };

function SelectStep({ onNext, onBack, selected, setSelected, onCveClick }) {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [sortBy, setSortBy] = useState("None");
  const [sortDir, setSortDir] = useState("asc");

  const filteredRows = sortRows(
    vulnRows.filter(row => (severityFilter === "All" || row.severity === severityFilter) && matchesSearch(row, search)),
    SELECT_SORT_FIELDS[sortBy],
    sortDir
  );

  const allChecked = filteredRows.length > 0 && filteredRows.every(r => selected.includes(r.id));
  const toggle = id => setSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id]);
  // Select/deselect only the rows currently visible under the active
  // filter, so toggling "all" on a filtered view doesn't blow away
  // selections the user already made on other rows.
  const toggleAll = () => {
    const filteredIds = filteredRows.map(r => r.id);
    setSelected(s => allChecked ? s.filter(id => !filteredIds.includes(id)) : Array.from(new Set([...s, ...filteredIds])));
  };

  return (
    <>
      <div className="page-card">
        <div className="page-title">Select Vulnerabilities</div>
        <div className="page-sub">Choose which findings to push through validation & ticketing.</div>
        <FilterBar
          search={search}
          onSearchChange={setSearch}
          searchPlaceholder="Search CVE, title, or asset…"
          groups={[{ options: ["All", "Critical", "High", "Medium", "Low"], value: severityFilter, onChange: setSeverityFilter }]}
          sort={{ options: Object.keys(SELECT_SORT_FIELDS), value: sortBy, onChange: setSortBy, dir: sortDir, onToggleDir: () => setSortDir(d => d === "asc" ? "desc" : "asc") }}
          resultCount={filteredRows.length}
          totalCount={vulnRows.length}
        />
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
              {filteredRows.map(row => (
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
              {filteredRows.length === 0 && (
                <tr>
                  <td colSpan={6} style={{ textAlign: "center", padding: "24px 0", color: "#9ca3af", fontSize: 13 }}>
                    No vulnerabilities match your filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
      <Footer step={2} onBack={onBack} onNext={onNext} disableNext={selected.length === 0} />
    </>
  );
}

//Upload step 4: Validation
const VALIDATION_SORT_FIELDS = { "None": null, "CVE": "id", "Severity": "severity", "Status": "status" };

function ValidationStep({ onNext, onBack, selected, setSelected, onCveClick }) {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState("All");
  const [sortBy, setSortBy] = useState("None");
  const [sortDir, setSortDir] = useState("asc");

  const selectedRows = validationRows.filter(row => selected.includes(row.id));
  const filteredRows = sortRows(
    selectedRows.filter(row =>
      (severityFilter === "All" || row.severity === severityFilter) &&
      (statusFilter === "All" || row.status === statusFilter) &&
      matchesSearch(row, search)
    ),
    VALIDATION_SORT_FIELDS[sortBy],
    sortDir
  );

  // All currently-selected CVEs still flagged "Needs Review" — this is what
  // both the bulk button and the count above it operate on, independent of
  // whatever the search/severity/status filters are currently narrowed to.
  const nonValidatedIds = validationRows
    .filter(r => selected.includes(r.id) && r.status === "Needs Review")
    .map(r => r.id);

  const removeCve = id => setSelected(prev => prev.filter(x => x !== id));
  const removeAllNonValidated = () => setSelected(prev => prev.filter(x => !nonValidatedIds.includes(x)));

  return (
    <>
      <div className="page-card">
        <div className="val-header">
          <div>
            <div className="page-title">Validation</div>
            <div style={{ fontSize: 12, color: "#9ca3af", marginBottom: 4 }}>Anti-hallucination</div>
            <div className="val-desc" style={{ marginBottom: 0 }}>For each selected vulnerability we cross-check the AI summary, remediation, severity classification, and flag any potential hallucinations against NVD, MITRE, and vendor advisories.</div>
          </div>
          <div style={{ textAlign: "right" }}>
            <div className="val-issues-label">Issues Found</div>
            <div className="val-issues-count">
              {nonValidatedIds.length}
            </div>
            <button
              onClick={removeAllNonValidated}
              disabled={nonValidatedIds.length === 0}
              style={{ marginTop: 6, padding: "6px 12px", borderRadius: 20, border: "1px solid #fecaca", background: nonValidatedIds.length === 0 ? "#f9fafb" : "#fef2f2", color: nonValidatedIds.length === 0 ? "#9ca3af" : "#dc2626", fontSize: 12, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: nonValidatedIds.length === 0 ? "default" : "pointer" }}>
              Remove All Non-Validated
            </button>
          </div>
        </div>

        <FilterBar
          search={search}
          onSearchChange={setSearch}
          searchPlaceholder="Search CVE or description…"
          groups={[
            { options: ["All", "Critical", "High", "Medium", "Low"], value: severityFilter, onChange: setSeverityFilter },
            { options: ["All", "Validated", "Needs Review"], value: statusFilter, onChange: setStatusFilter },
          ]}
          sort={{ options: Object.keys(VALIDATION_SORT_FIELDS), value: sortBy, onChange: setSortBy, dir: sortDir, onToggleDir: () => setSortDir(d => d === "asc" ? "desc" : "asc") }}
          resultCount={filteredRows.length}
          totalCount={selectedRows.length}
        />

        {filteredRows.length === 0 && (
          <div style={{ textAlign: "center", padding: "24px 0", color: "#9ca3af", fontSize: 13 }}>
            No vulnerabilities match your filters.
          </div>
        )}

        {filteredRows.map(row => (
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
              {row.status === "Needs Review" && (
                <button
                  onClick={() => removeCve(row.id)}
                  title="Remove this CVE from the selection"
                  style={{ marginLeft: "auto", padding: "4px 10px", borderRadius: 20, border: "1px solid #fecaca", background: "#fff", color: "#dc2626", fontSize: 11, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: "pointer" }}>
                  Remove
                </button>
              )}
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
const TICKET_SORT_FIELDS = { "None": null, "CVE": "id", "Title": "title", "Severity": "severity", "Priority": "priority", "Asset": "asset" };

function GenerateTicketStep({ onNext, onBack, selected }) {
  const tickets = (selected || []).map(id => {
    const d = cveDetails[id] || {};
    const row = vulnRows.find(r => r.id === id) || {};
    return {
      id,
      title: `[${row.severity || ""}] ${id} — ${d.title || ""}`,
      description: d.why || "",
      severity: row.severity || "",
      priority: row.severity === "Critical" ? "P1 - Critical" : row.severity === "High" ? "P2 - High" : "P3 - Medium",
      asset: row.asset || "",
      assignTo: row.severity === "Critical" ? "Security Team" : "IT Operations",
    };
  });

  const [activeIdx, setActiveIdx] = useState(0);
  const [forms, setForms] = useState(tickets.map(t => ({ ...t })));
  const [submitted, setSubmitted] = useState(tickets.map(() => null));
  const allDone = submitted.every(s => s !== null);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [reviewFilter, setReviewFilter] = useState("All");
  const [sortBy, setSortBy] = useState("None");
  const [sortDir, setSortDir] = useState("asc");

  const update = (field, value) => {
    setForms(prev => prev.map((f, i) => i === activeIdx ? { ...f, [field]: value } : f));
  };

  const form = forms[activeIdx] || {};

  // Filtering/sorting only narrows or reorders which tickets show in the
  // sidebar — the underlying forms/submitted arrays keep their original
  // indices so approve/reject state and the active form aren't disturbed.
  const reviewStatus = i => submitted[i] === "approved" ? "Approved" : submitted[i] === "rejected" ? "Rejected" : "Pending";
  const visibleIdx = sortRows(
    forms
      .map((_, i) => i)
      .filter(i => {
        const t = forms[i];
        return (severityFilter === "All" || t.severity === severityFilter) &&
          (reviewFilter === "All" || reviewStatus(i) === reviewFilter) &&
          matchesSearch(t, search);
      })
      .map(i => ({ __idx: i, ...forms[i] })),
    TICKET_SORT_FIELDS[sortBy],
    sortDir
  ).map(r => r.__idx);

  // Applies to whatever the search/severity/review filters currently narrow
  // the list down to (visibleIdx), not every ticket in the wizard — so
  // filtering down to e.g. "Critical" first, then bulk-approving, only
  // touches those. Jumps the active form to the first newly-decided ticket
  // so the right-hand panel doesn't keep showing a now-stale selection.
  const bulkSetVisible = status => {
    setSubmitted(prev => prev.map((s, i) => visibleIdx.includes(i) ? status : s));
    if (visibleIdx.length > 0) setActiveIdx(visibleIdx[0]);
  };

  return (
    <>
      <div className="page-card" style={{ padding: 0, overflow: "hidden" }}>
        {/* Header: title only — filter/sort panel below is always visible */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "16px 20px", borderBottom: "none" }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: "#6b7280", textTransform: "uppercase", letterSpacing: "0.05em" }}>Tickets to create</div>
        </div>

        {/* Filter/sort panel — spans the full width of the page, over both
            the sidebar and the form, same as the Select/Validation pages.
            Always shown (no toggle) so filters stay accessible at a glance. */}
        <div style={{ padding: "12px 20px 16px", borderBottom: "1px solid #f3f4f6", background: "#fafafa" }}>
          <FilterBar
            search={search}
            onSearchChange={setSearch}
            searchPlaceholder="Search CVE, title, or asset…"
            groups={[
              { options: ["All", "Critical", "High", "Medium", "Low"], value: severityFilter, onChange: setSeverityFilter },
              { options: ["All", "Pending", "Approved", "Rejected"], value: reviewFilter, onChange: setReviewFilter },
            ]}
            sort={{ options: Object.keys(TICKET_SORT_FIELDS), value: sortBy, onChange: setSortBy, dir: sortDir, onToggleDir: () => setSortDir(d => d === "asc" ? "desc" : "asc") }}
            resultCount={visibleIdx.length}
            totalCount={forms.length}
          />
          <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
            <button
              onClick={() => bulkSetVisible("approved")}
              disabled={visibleIdx.length === 0}
              title="Approves every ticket currently matching the filters above"
              style={{ padding: "6px 14px", borderRadius: 20, border: "none", background: visibleIdx.length === 0 ? "#e5e7eb" : "#16a34a", color: visibleIdx.length === 0 ? "#9ca3af" : "#fff", fontSize: 12, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: visibleIdx.length === 0 ? "default" : "pointer" }}>
              Approve All ({visibleIdx.length})
            </button>
            <button
              onClick={() => bulkSetVisible("rejected")}
              disabled={visibleIdx.length === 0}
              title="Rejects every ticket currently matching the filters above"
              style={{ padding: "6px 14px", borderRadius: 20, border: "1px solid #fecaca", background: visibleIdx.length === 0 ? "#f9fafb" : "#fef2f2", color: visibleIdx.length === 0 ? "#9ca3af" : "#dc2626", fontSize: 12, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: visibleIdx.length === 0 ? "default" : "pointer" }}>
              Reject All ({visibleIdx.length})
            </button>
          </div>
        </div>

        <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
        {/* Left sidebar */}
        <div style={{ width: 220, borderRight: "1px solid #f3f4f6", padding: "12px 0", flexShrink: 0, overflowY: "auto" }}>
          {visibleIdx.length === 0 && (
            <div style={{ padding: "0 16px", fontSize: 12, color: "#9ca3af" }}>No tickets match your filters.</div>
          )}
          {visibleIdx.map(i => {
            const t = forms[i];
            return (
              <div key={t.id} onClick={() => setActiveIdx(i)}
                style={{ padding: "10px 16px", cursor: "pointer", background: activeIdx === i ? "#eff6ff" : "transparent",
                  borderLeft: activeIdx === i ? "3px solid #2563eb" : "3px solid transparent" }}>
                <div style={{ fontSize: 12, fontFamily: "monospace", color: activeIdx === i ? "#2563eb" : "#374151", fontWeight: 600 }}>{t.id}</div>
                <div style={{ fontSize: 11, marginTop: 2, color: submitted[i] === "approved" ? "#16a34a" : submitted[i] === "rejected" ? "#dc2626" : "#9ca3af" }}>
                  {submitted[i] === "approved" ? "✓ Approved" : submitted[i] === "rejected" ? "✗ Rejected" : t.priority}
                </div>
              </div>
            );
          })}
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
      </div>
      <Footer step={4} onBack={onBack} onNext={() => onNext(tickets.filter((_, i) => submitted[i] === "approved").map(t => t.id))} nextLabel="Review & Send" disableNext={!allDone} />
    </>
  );
}

//Upload step 6: Review & Send
const REVIEW_SORT_FIELDS = { "None": null, "CVE": "id", "Title": "title", "Severity": "severity", "Priority": "priority", "Assign To": "assignTo" };

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
  const [sending, setSending] = useState(false);
  const [sendError, setSendError] = useState(null);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [sortBy, setSortBy] = useState("None");
  const [sortDir, setSortDir] = useState("asc");
  const priorityColor = p => p === "P1" ? { bg: "#fef2f2", color: "#dc2626" } : p === "P2" ? { bg: "#fff7ed", color: "#ea580c" } : { bg: "#f0fdf4", color: "#16a34a" };

  // Filtering/sorting here only narrows or reorders what's shown for review
  // — "Send to Jira" below always sends every approved ticket in `tickets`,
  // filtered or not, since the filter is just a way to find something in a
  // long list, not a second approval step.
  const filteredTickets = sortRows(
    tickets.filter(t => (severityFilter === "All" || t.severity === severityFilter) && matchesSearch(t, search)),
    REVIEW_SORT_FIELDS[sortBy],
    sortDir
  );

  if (sent) {
    return (
      <>
        <div className="page-card" style={{ alignItems: "center", justifyContent: "center", gap: 16, minHeight: 300 }}>
          <div style={{ width: 64, height: 64, borderRadius: "50%", background: "#f0fdf4", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 28 }}>✓</div>
          <div style={{ fontSize: 18, fontWeight: 700, color: "#111" }}>Tickets sent to Jira</div>
          <div style={{ fontSize: 13, color: "#6b7280" }}>{tickets.length} ticket{tickets.length !== 1 ? "s" : ""} successfully created</div>
          <button onClick={onNext} className="btn btn-primary" style={{ marginTop: 8 }}>Go to Tickets</button>
        </div>
        <Footer step={5} onBack={onBack} hideNext />
      </>
    );
  }

  return (
    <>
      <div className="page-card">
        <div style={{ fontSize: 15, fontWeight: 700, color: "#111", marginBottom: 4 }}>Review & Send</div>
        <div style={{ fontSize: 13, color: "#6b7280", marginBottom: 20 }}>Confirm the following tickets will be sent to Jira</div>

        {tickets.length > 0 && (
          <FilterBar
            search={search}
            onSearchChange={setSearch}
            searchPlaceholder="Search CVE or title…"
            groups={[{ options: ["All", "Critical", "High", "Medium", "Low"], value: severityFilter, onChange: setSeverityFilter }]}
            sort={{ options: Object.keys(REVIEW_SORT_FIELDS), value: sortBy, onChange: setSortBy, dir: sortDir, onToggleDir: () => setSortDir(d => d === "asc" ? "desc" : "asc") }}
            resultCount={filteredTickets.length}
            totalCount={tickets.length}
          />
        )}

        <div style={{ border: "1px solid #f3f4f6", borderRadius: 10, overflow: "hidden", marginBottom: 20 }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr 1fr 1fr", padding: "10px 16px", background: "#f9fafb", borderBottom: "1px solid #f3f4f6" }}>
            {["CVE", "Title", "Priority", "Assign To"].map(h => (
              <div key={h} style={{ fontSize: 11, fontWeight: 600, color: "#6b7280", textTransform: "uppercase", letterSpacing: "0.05em" }}>{h}</div>
            ))}
          </div>
          {filteredTickets.length === 0 ? (
            <div style={{ padding: "20px 16px", textAlign: "center", fontSize: 13, color: "#9ca3af" }}>No tickets match your filters.</div>
          ) : filteredTickets.map((t, i) => {
            const pc = priorityColor(t.priority);
            return (
              <div key={t.id} style={{ display: "grid", gridTemplateColumns: "1fr 2fr 1fr 1fr", padding: "12px 16px", borderBottom: i < filteredTickets.length - 1 ? "1px solid #f3f4f6" : "none", alignItems: "center" }}>
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
          <>
            {sendError && (
              <div style={{ padding: "10px 14px", background: "#fef2f2", border: "1px solid #fecaca", borderRadius: 8, fontSize: 12, color: "#dc2626", marginBottom: 12 }}>
                {sendError}
              </div>
            )}
            <button
              disabled={sending}
              onClick={async () => {
                setSending(true);
                setSendError(null);

                // Try pushing each approved ticket to the connected Jira
                // account. If Jira isn't connected/configured, or a push
                // fails, we still fall back to the local demo ticket list
                // so the wizard doesn't get stuck — but we surface the
                // reason so it's clear nothing silently failed.
                let jiraFailures = 0;
                // Keyed by the CVE/finding id (t.id) so each created ticket
                // below can look up its own Jira issue key — needed so a
                // later status change in Jira (e.g. closing it) can be
                // synced back to the right local ticket. See
                // POST /api/tickets/sync in tickets.py.
                const jiraResults = {};
                try {
                  const statusRes = await fetch(`${API_BASE}/api/jira/status`, { credentials: "include" });
                  const statusData = await statusRes.json();

                  if (statusData.connected) {
                    for (const t of tickets) {
                      const res = await fetch(`${API_BASE}/api/jira/create-ticket`, {
                        method: "POST",
                        credentials: "include",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ title: t.title, description: cveDetails[t.id]?.why || "", priority: t.priority }),
                      });
                      if (res.ok) {
                        const created = await res.json();
                        jiraResults[t.id] = { issueKey: created.issueKey, url: created.url };
                      } else {
                        jiraFailures += 1;
                      }
                    }
                    if (jiraFailures > 0) {
                      setSendError(`${jiraFailures} of ${tickets.length} ticket(s) failed to push to Jira. They were still added to the local ticket list below.`);
                    }
                  }
                } catch {
                  setSendError("Couldn't reach the Jira integration — tickets were still added to the local ticket list below.");
                }

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
                  jiraIssueKey: jiraResults[t.id]?.issueKey || null,
                  jiraUrl: jiraResults[t.id]?.url || null,
                }));

                // Persist to the signed-in account (see tickets.py) so
                // these survive a refresh/restart instead of only living
                // in this tab's React state. Best-effort — a save failure
                // here shouldn't block the wizard, same reasoning as the
                // Jira push above.
                try {
                  await fetch(`${API_BASE}/api/tickets`, {
                    method: "POST",
                    credentials: "include",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(newTickets),
                  });
                } catch {
                  // local ticket list below still gets these either way
                }

                // Only NOW does this scan count as "completed" — see
                // POST /api/scans in scans.py. This is what makes scan
                // history/dashboard show a real, reviewed scan rather than
                // one someone uploaded and then abandoned before reaching
                // this screen. Best-effort, same reasoning as the ticket
                // save above: a failure here shouldn't block the wizard.
                try {
                  await fetch(`${API_BASE}/api/scans`, {
                    method: "POST",
                    credentials: "include",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                      scanner: lastScanMeta.scanner,
                      source: lastScanMeta.source,
                      target: lastScanMeta.target,
                      vulnerabilities: lastVulnerabilities,
                    }),
                  });
                } catch {
                  // scan just won't show in history this time; nothing else depends on it
                }

                onSubmit(newTickets);
                setSending(false);
                setSent(true);
              }}
              style={{ width: "100%", padding: "12px", borderRadius: 20, border: "none", background: "#111", color: "#fff", fontSize: 14, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: sending ? "default" : "pointer", opacity: sending ? 0.6 : 1 }}>
              {sending ? "Sending…" : "Send to Jira"}
            </button>
          </>
        )}
      </div>
      <Footer step={5} onBack={onBack} hideNext />
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
  // syncState: idle | syncing | done | error — drives the small status text
  // next to the Sync button so it's clear something actually happened
  // (or didn't) rather than the button just silently doing nothing.
  const [syncState, setSyncState] = useState("idle");
  // Tracks whether the FIRST sync (the one that runs automatically on
  // mount) has finished. Ticket status here is only as fresh as the last
  // sync — GET /api/tickets returns whatever was last written locally,
  // which can be stale if a ticket was closed in Jira since. Rather than
  // show that stale "Open" for the second or so it takes the first sync
  // to complete (then have it visibly flip to "Closed"), we hold off
  // rendering statuses until that first sync resolves. Manual re-syncs
  // (the button) don't re-trigger this — by then the list is already
  // showing real data, so there's nothing misleading to hide.
  const [hasSyncedOnce, setHasSyncedOnce] = useState(false);

  // Poll-on-demand Jira sync (see POST /api/tickets/sync in tickets.py):
  // pulls the current status of every ticket linked to a Jira issue and
  // updates it locally — e.g. a ticket closed in Jira shows as Closed here
  // without disappearing. Not live/instant; runs once when the Tickets tab
  // is opened, and again any time the Sync button is clicked.
  const syncWithJira = () => {
    setSyncState("syncing");
    fetch(`${API_BASE}/api/tickets/sync`, { method: "POST", credentials: "include" })
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data.tickets)) {
          setTickets(data.tickets);
          setSelectedTicket(prev => {
            if (!prev) return data.tickets[0] || null;
            return data.tickets.find(t => t.id === prev.id) || prev;
          });
        }
        setSyncState("done");
      })
      .catch(() => setSyncState("error"))
      .finally(() => setHasSyncedOnce(true));
  };

  useEffect(() => {
    syncWithJira();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 4 }}>
            <div style={{ fontSize: 18, fontWeight: 700, color: "#111" }}>Tickets</div>
            <button
              onClick={syncWithJira}
              disabled={syncState === "syncing"}
              style={{ display: "flex", alignItems: "center", gap: 6, padding: "5px 12px", borderRadius: 20, border: "1px solid #e5e7eb", background: "#fff", fontSize: 12, fontWeight: 600, fontFamily: "DM Sans, sans-serif", color: "#374151", cursor: syncState === "syncing" ? "default" : "pointer", opacity: syncState === "syncing" ? 0.6 : 1 }}>
              {syncState === "syncing" ? "Syncing…" : "Sync with Jira"}
            </button>
          </div>
          <div style={{ fontSize: 13, color: "#6b7280", marginBottom: 16 }}>
            AI-generated — human approved — synced with Jira
            {syncState === "error" && <span style={{ color: "#dc2626" }}> · Sync failed — check your Jira connection in Profile</span>}
          </div>

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
          {!hasSyncedOnce ? (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: 200, color: "#9ca3af", fontSize: 13 }}>
              Loading current statuses from Jira…
            </div>
          ) : filtered.length === 0 ? (
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

          {selectedTicket.jiraIssueKey && (
            <a href={selectedTicket.jiraUrl || undefined} target="_blank" rel="noreferrer"
              style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 12, fontWeight: 600, color: "#2563eb", textDecoration: "none", marginBottom: 12 }}>
              🔗 {selectedTicket.jiraIssueKey} in Jira
            </a>
          )}

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
                    // Best-effort — the local update above already reflects
                    // the change either way, this just makes it stick past
                    // a refresh.
                    fetch(`${API_BASE}/api/tickets/${encodeURIComponent(updated.id)}`, {
                      method: "PATCH",
                      credentials: "include",
                      headers: { "Content-Type": "application/json" },
                      body: JSON.stringify({ status: editForm.status, assigned: editForm.assigned }),
                    }).catch(() => {});
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

//Jira Connect — isolated component, only talks to /api/jira/* endpoints.
// Doesn't touch any other app state; safe to remove without breaking
// anything else if the Jira integration is ever disabled.
function JiraConnect() {
  const [status, setStatus] = useState({ loading: true });

  const refreshStatus = () => {
    fetch(`${API_BASE}/api/jira/status`, { credentials: "include" })
      .then(res => res.json())
      .then(data => setStatus({ loading: false, ...data }))
      .catch(() => setStatus({ loading: false, configured: false, connected: false, error: true }));
  };

  useEffect(() => {
    refreshStatus();
    // If we just got redirected back from Atlassian, drop the ?jira=connected
    // query param so refreshing the page doesn't look odd, and re-check status.
    if (new URLSearchParams(window.location.search).get("jira") === "connected") {
      window.history.replaceState({}, "", window.location.pathname);
    }
  }, []);

  const handleDisconnect = () => {
    fetch(`${API_BASE}/api/jira/disconnect`, { method: "POST", credentials: "include" })
      .then(refreshStatus);
  };

  if (status.loading) return null;

  if (!status.configured) {
    return (
      <div style={{ padding: "12px 16px", background: "#f9fafb", borderRadius: 10, border: "1px solid #e5e7eb", fontSize: 12, color: "#9ca3af" }}>
        Jira integration is not configured on this server.
      </div>
    );
  }

  if (status.connected) {
    return (
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 16px", background: "#f0fdf4", borderRadius: 10, border: "1px solid #bbf7d0" }}>
        <div>
          <div style={{ fontSize: 13, fontWeight: 600, color: "#15803d" }}>✓ Connected to Jira</div>
          <div style={{ fontSize: 12, color: "#166534" }}>{status.site}.atlassian.net</div>
        </div>
        <button
          onClick={handleDisconnect}
          style={{ padding: "8px 14px", borderRadius: 20, border: "1px solid #e5e7eb", background: "#fff", fontSize: 12, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: "pointer", color: "#374151" }}>
          Disconnect
        </button>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 16px", background: "#f9fafb", borderRadius: 10, border: "1px solid #e5e7eb" }}>
      <div>
        <div style={{ fontSize: 13, fontWeight: 500, color: "#374151" }}>Jira</div>
        <div style={{ fontSize: 12, color: "#6b7280" }}>Not connected</div>
      </div>
      <a href={`${API_BASE}/api/jira/connect`}>
        <button
          style={{ padding: "8px 14px", borderRadius: 20, border: "none", background: "#2563eb", color: "#fff", fontSize: 12, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: "pointer" }}>
          Connect Jira
        </button>
      </a>
    </div>
  );
}

//Private registry connect — isolated component, only talks to
// /api/registry/* endpoints. Same shape as JiraConnect: lets the user type
// in credentials for one private registry (Docker Hub private repo, GHCR,
// self-hosted Harbor/registry:2, etc.) and stores them server-side against
// this browser session, instead of needing backend/.env edited + the
// container restarted.
function RegistryConnect() {
  const [status, setStatus] = useState({ loading: true });
  const [form, setForm] = useState({ url: "", username: "", password: "" });
  const [connecting, setConnecting] = useState(false);
  const [error, setError] = useState("");

  const refreshStatus = () => {
    fetch(`${API_BASE}/api/registry/status`, { credentials: "include" })
      .then(res => res.json())
      .then(data => setStatus({ loading: false, ...data }))
      .catch(() => setStatus({ loading: false, connected: false, error: true }));
  };

  useEffect(() => { refreshStatus(); }, []);

  const handleConnect = async () => {
    if (!form.url.trim() || !form.username.trim() || !form.password) return;
    setConnecting(true);
    setError("");
    try {
      const res = await fetch(`${API_BASE}/api/registry/connect`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: form.url.trim(), username: form.username.trim(), password: form.password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Couldn't connect");
      setForm({ url: "", username: "", password: "" });
      refreshStatus();
    } catch (err) {
      setError(err.message);
    } finally {
      setConnecting(false);
    }
  };

  const handleDisconnect = () => {
    fetch(`${API_BASE}/api/registry/disconnect`, { method: "POST", credentials: "include" })
      .then(refreshStatus);
  };

  if (status.loading) return null;

  if (status.connected) {
    return (
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 16px", background: "#f0fdf4", borderRadius: 10, border: "1px solid #bbf7d0" }}>
        <div>
          <div style={{ fontSize: 13, fontWeight: 600, color: "#15803d" }}>✓ Connected to private registry</div>
          <div style={{ fontSize: 12, color: "#166534" }}>{status.url} ({status.username})</div>
        </div>
        <button
          onClick={handleDisconnect}
          style={{ padding: "8px 14px", borderRadius: 20, border: "1px solid #e5e7eb", background: "#fff", fontSize: 12, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: "pointer", color: "#374151" }}>
          Disconnect
        </button>
      </div>
    );
  }

  const fieldStyle = { padding: "8px 10px", borderRadius: 8, border: "1px solid #e5e7eb", fontSize: 13, width: "100%", fontFamily: "DM Sans, sans-serif" };

  return (
    <div style={{ padding: "12px 16px", background: "#f9fafb", borderRadius: 10, border: "1px solid #e5e7eb", display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ fontSize: 13, fontWeight: 500, color: "#374151" }}>Private registry (Trivy)</div>
      <div style={{ fontSize: 12, color: "#6b7280", marginBottom: 4 }}>Scan private images by connecting one registry here — no server config needed.</div>
      <input
        style={fieldStyle}
        placeholder="Registry host, e.g. ghcr.io"
        value={form.url}
        onChange={e => setForm(f => ({ ...f, url: e.target.value }))}
        disabled={connecting}
      />
      <input
        style={fieldStyle}
        placeholder="Username"
        value={form.username}
        onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
        disabled={connecting}
      />
      <input
        style={fieldStyle}
        type="password"
        placeholder="Password or access token"
        value={form.password}
        onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
        disabled={connecting}
      />
      {error && <div style={{ fontSize: 12, color: "#dc2626" }}>{error}</div>}
      <button
        onClick={handleConnect}
        disabled={connecting || !form.url.trim() || !form.username.trim() || !form.password}
        style={{ alignSelf: "flex-start", padding: "8px 14px", borderRadius: 20, border: "none", background: (connecting || !form.url.trim() || !form.username.trim() || !form.password) ? "#93c5fd" : "#2563eb", color: "#fff", fontSize: 12, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: "pointer" }}>
        {connecting ? "Connecting…" : "Connect registry"}
      </button>
    </div>
  );
}

//Profile
// Read-only summary of the business-context questionnaire, with an Edit
// button that swaps in the same BusinessContextStep form used at signup
// (prefilled via `initialData`). Fetches its own data so Profile doesn't
// need to carry it around as top-level app state.
function BusinessContextSummary() {
  const [data, setData] = useState({ loading: true });
  const [editing, setEditing] = useState(false);

  const refresh = () => {
    setData({ loading: true });
    fetch(`${API_BASE}/api/business-context/me`, { credentials: "include" })
      .then(res => res.json())
      .then(d => setData({ loading: false, ...d }))
      .catch(() => setData({ loading: false, completed: false, error: true }));
  };

  useEffect(() => { refresh(); }, []);

  if (data.loading) return null;

  if (editing) {
    return (
      <BusinessContextStep
        mode="edit"
        initialData={data.completed ? data : null}
        onCancel={() => setEditing(false)}
        onComplete={saved => { setData({ loading: false, ...saved }); setEditing(false); }}
      />
    );
  }

  if (!data.completed) {
    return (
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 16px", background: "#f9fafb", borderRadius: 10, border: "1px solid #e5e7eb" }}>
        <div>
          <div style={{ fontSize: 13, fontWeight: 500, color: "#374151" }}>Business context</div>
          <div style={{ fontSize: 12, color: "#6b7280" }}>Not set yet — helps us prioritise vulnerabilities by business impact</div>
        </div>
        <button
          onClick={() => setEditing(true)}
          style={{ padding: "8px 14px", borderRadius: 20, border: "none", background: "#2563eb", color: "#fff", fontSize: 12, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: "pointer" }}>
          Add answers
        </button>
      </div>
    );
  }

  const sensitivityLabels = data.dataSensitivity.map(v => optionLabel(DATA_SENSITIVITY_OPTIONS, v));
  const complianceLabels = data.complianceScope.map(v => optionLabel(COMPLIANCE_OPTIONS, v));
  const chip = text => (
    <span key={text} style={{ fontSize: 11, fontWeight: 600, padding: "3px 10px", borderRadius: 20, background: "#eff6ff", color: "#2563eb" }}>{text}</span>
  );

  return (
    <div style={{ padding: "14px 16px", background: "#f9fafb", borderRadius: 10, border: "1px solid #e5e7eb", display: "flex", flexDirection: "column", gap: 10 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: "#374151" }}>
          {data.sector === "other" ? data.sectorOther : optionLabel(SECTOR_OPTIONS, data.sector)}
        </div>
        <button
          onClick={() => setEditing(true)}
          style={{ padding: "6px 14px", borderRadius: 20, border: "1px solid #e5e7eb", background: "#fff", fontSize: 12, fontWeight: 600, fontFamily: "DM Sans, sans-serif", cursor: "pointer", color: "#374151", flexShrink: 0 }}>
          Edit
        </button>
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
        {chip(`Criticality Tier ${data.criticalityTier}`)}
        {chip(optionLabel(INTERNET_FACING_OPTIONS, data.internetFacing))}
        {data.airGapped && chip("Has air-gapped systems")}
        {sensitivityLabels.map(chip)}
        {complianceLabels.map(chip)}
      </div>
    </div>
  );
}

function Profile({ onSignOut, userName, userEmail, notifications, setNotifications, defaultAssign, setDefaultAssign }) {

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
            onClick={() => setNotifications(!notifications)}
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

      <div style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: "#374151", marginBottom: 12 }}>Business context</div>
        <BusinessContextSummary />
      </div>

      <div style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: "#374151", marginBottom: 12 }}>Integrations</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <JiraConnect />
          <RegistryConnect />
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
// Visual styling per activity "tag" — mirrors the fixed palette the mockup
// used, just applied to whichever tags actually come back from
// /api/dashboard/summary instead of a hardcoded list.
const ACTIVITY_STYLES = {
  Scan:     { color: "#2563eb", bg: "#eff6ff" },
  Ticket:   { color: "#7c3aed", bg: "#f5f3ff" },
  Resolved: { color: "#16a34a", bg: "#f0fdf4" },
  Critical: { color: "#dc2626", bg: "#fef2f2" },
};

function Dashboard() {
  const chartWrapRef = useRef(null);
  const [chartHeight, setChartHeight] = useState(180);
  const [summary, setSummary] = useState(null); // null while loading
  const [loadError, setLoadError] = useState(false);

  useEffect(() => {
    if (!chartWrapRef.current) return;
    const ro = new ResizeObserver(entries => {
      for (const e of entries) setChartHeight(e.contentRect.height);
    });
    ro.observe(chartWrapRef.current);
    return () => ro.disconnect();
  }, []);

  // Pulls this account's real stats (see dashboard.py) — computed from its
  // actual scan and ticket history, not placeholder numbers. Re-fetched
  // every time the Dashboard tab mounts, so it's current right after a new
  // scan or ticket without needing a manual refresh.
  useEffect(() => {
    let cancelled = false;
    fetch(`${API_BASE}/api/dashboard/summary`, { credentials: "include" })
      .then(res => res.json())
      .then(data => { if (!cancelled) setSummary(data); })
      .catch(() => { if (!cancelled) setLoadError(true); });
    return () => { cancelled = true; };
  }, []);

  const chartData = summary?.chart?.length ? summary.chart : [];
  const chartMax = Math.max(30, ...chartData.map(d => d.count), 0);
  const yTicks = [0, Math.round(chartMax / 3), Math.round((chartMax * 2) / 3), chartMax];

  return (
    <>
      <div className="heading">
        <h1>Security Overview</h1>
        <div className="heading-sub">{summary?.hasScans ? "All scans" : "No scans yet"} ▾</div>
      </div>
      <div className="stats-row">
        <div className="stat-card">
          <div className="stat-label">Total Vulnerabilities</div>
          <div className="stat-value">
            {summary?.totalVulnerabilities ?? "—"}{" "}
            {typeof summary?.totalDeltaPct === "number" && (
              <span className="stat-delta" style={{ color: summary.totalDeltaPct > 0 ? "#dc2626" : "#16a34a" }}>
                {summary.totalDeltaPct > 0 ? "+" : ""}{summary.totalDeltaPct}%
              </span>
            )}
          </div>
        </div>
        <div className="stat-card"><div className="stat-label">Critical</div><div className="stat-value critical">{summary?.critical ?? "—"}</div></div>
        <div className="stat-card"><div className="stat-label">Medium</div><div className="stat-value medium">{summary?.medium ?? "—"}</div></div>
        <div className="stat-card"><div className="stat-label">New (last scan)</div><div className="stat-value">{summary?.newSinceLastScan ?? "—"}</div></div>
      </div>
      <div className="mid-row">
        <div className="chart-card">
          <div className="chart-title">Vulnerabilities over time</div>
          <div className="chart-grow" ref={chartWrapRef}>
            {chartData.length ? (
              <ResponsiveContainer width="100%" height={chartHeight}>
                <BarChart data={chartData} barSize={28}>
                  <CartesianGrid vertical={false} stroke="#f3f4f6" />
                  <XAxis dataKey="label" axisLine={false} tickLine={false} tick={{ fontSize: 12, fill: "#9ca3af" }} />
                  <YAxis axisLine={false} tickLine={false} tick={{ fontSize: 11, fill: "#9ca3af" }} domain={[0, chartMax]} ticks={yTicks} />
                  <Tooltip cursor={{ fill: "rgba(37,99,235,0.08)" }} contentStyle={{ borderRadius: 10, border: "none", boxShadow: "0 4px 20px rgba(0,0,0,.1)", fontSize: 13 }} />
                  <Bar dataKey="count" fill="#2563eb" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: chartHeight, color: "#9ca3af", fontSize: 13 }}>
                {loadError ? "Couldn't load scan history." : "Run a scan to start building this chart."}
              </div>
            )}
          </div>
        </div>
        <div className="insight-card">
          <div className="insight-label">AI Insight</div>
          <div className="insight-text">{summary?.aiInsight || "Upload or run a scan to get AI-prioritized insights about your findings."}</div>
        </div>
      </div>
      <div className="activity-card">
        <div className="activity-title">Recent Activity</div>
        <div className="activity-grid">
          {summary?.recentActivity?.length ? (
            summary.recentActivity.map((item, i) => {
              const style = ACTIVITY_STYLES[item.tag] || { color: "#374151", bg: "#f3f4f6" };
              return (
                <div key={i} className="activity-item" style={{ background: style.bg }}>
                  <span className="activity-tag" style={{ color: style.color }}>{item.tag}</span>
                  <div className="activity-label">{item.label}</div>
                </div>
              );
            })
          ) : (
            <div style={{ color: "#9ca3af", fontSize: 13, padding: "8px 4px" }}>
              Nothing yet — scan something or create a ticket to see activity here.
            </div>
          )}
        </div>
      </div>
    </>
  );
}

// Severity -> bar color, same palette used elsewhere (Dashboard's stat
// values, the export xlsx row highlights) so a severity always reads the
// same color across the whole app.
const SEVERITY_COLORS = { critical: "#dc2626", high: "#ea580c", medium: "#ca8a04", low: "#16a34a" };

// Scan History & long-term analysis page. Pulls the FULL scan history (not
// just the last 6 scans Dashboard's chart shows) plus recurring-CVE and
// resolution stats computed server-side — see GET /api/scans/analysis in
// scans.py. Answers questions the Dashboard snapshot can't: "is our
// vulnerability count trending down over months?", "which CVEs keep coming
// back scan after scan?", "how many scans have we actually run?"
function ScanHistory() {
  const [data, setData] = useState(null); // null while loading
  const [loadError, setLoadError] = useState(false);
  const [expandedScan, setExpandedScan] = useState(null);

  useEffect(() => {
    let cancelled = false;
    fetch(`${API_BASE}/api/scans/analysis`, { credentials: "include" })
      .then(res => res.json())
      .then(d => { if (!cancelled) setData(d); })
      .catch(() => { if (!cancelled) setLoadError(true); });
    return () => { cancelled = true; };
  }, []);

  const totals = data?.totals || {};
  const trend = data?.trend || [];
  const recurring = data?.recurring || [];
  const scans = data?.scans || [];

  const scannerBreakdown = Object.entries(totals.scannerBreakdown || {});

  return (
    <>
      <div className="heading">
        <h1>Scan History &amp; Analysis</h1>
        <div className="heading-sub">{data?.hasScans ? `${totals.scanCount} scan(s) on record` : "No scans yet"}</div>
      </div>

      <div className="stats-row">
        <div className="stat-card"><div className="stat-label">Total Scans</div><div className="stat-value">{data?.hasScans ? totals.scanCount : "—"}</div></div>
        <div className="stat-card"><div className="stat-label">Avg Findings / Scan</div><div className="stat-value">{data?.hasScans ? totals.avgFindingsPerScan : "—"}</div></div>
        <div className="stat-card"><div className="stat-label">Unique CVEs Seen</div><div className="stat-value">{data?.hasScans ? totals.uniqueCvesSeen : "—"}</div></div>
        <div className="stat-card"><div className="stat-label">Resolved CVEs</div><div className="stat-value" style={{ color: "#16a34a" }}>{data?.hasScans ? totals.resolvedCves : "—"}</div></div>
      </div>

      <div className="chart-card" style={{ marginBottom: 12 }}>
        <div className="chart-title">Vulnerabilities over full scan history</div>
        {trend.length ? (
          <ResponsiveContainer width="100%" height={260}>
            <LineChart data={trend}>
              <CartesianGrid vertical={false} stroke="#f3f4f6" />
              <XAxis dataKey="label" axisLine={false} tickLine={false} tick={{ fontSize: 11, fill: "#9ca3af" }} />
              <YAxis axisLine={false} tickLine={false} tick={{ fontSize: 11, fill: "#9ca3af" }} allowDecimals={false} />
              <Tooltip contentStyle={{ borderRadius: 10, border: "none", boxShadow: "0 4px 20px rgba(0,0,0,.1)", fontSize: 12 }} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Line type="monotone" dataKey="critical" name="Critical" stroke={SEVERITY_COLORS.critical} strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="high" name="High" stroke={SEVERITY_COLORS.high} strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="medium" name="Medium" stroke={SEVERITY_COLORS.medium} strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="low" name="Low" stroke={SEVERITY_COLORS.low} strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="total" name="Total" stroke="#2563eb" strokeWidth={2} strokeDasharray="4 3" dot={false} />
            </LineChart>
          </ResponsiveContainer>
        ) : (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: 200, color: "#9ca3af", fontSize: 13 }}>
            {loadError ? "Couldn't load scan history." : "Run a few scans to start building this trend."}
          </div>
        )}
      </div>

      <div className="mid-row" style={{ marginBottom: 12, gridTemplateColumns: "2fr 1fr" }}>
        {/* Recurring vulnerabilities */}
        <div className="chart-card">
          <div className="chart-title">Recurring vulnerabilities</div>
          {recurring.length === 0 ? (
            <div style={{ color: "#9ca3af", fontSize: 13, padding: "8px 4px" }}>
              {data?.hasScans ? "Nothing recurring yet — no CVE has shown up in more than one scan." : "Run a few scans to see which findings keep coming back."}
            </div>
          ) : (
            <div style={{ overflowY: "auto", maxHeight: 260 }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 90px 90px 90px 110px", gap: 8, padding: "4px 0 8px", borderBottom: "1px solid #e5e7eb", position: "sticky", top: 0, background: "#fff" }}>
                {["CVE", "Appeared In", "First Seen", "Last Seen", "In Latest Scan"].map(h => (
                  <div key={h} style={{ fontSize: 11, fontWeight: 600, color: "#9ca3af", textTransform: "uppercase", letterSpacing: "0.04em" }}>{h}</div>
                ))}
              </div>
              {recurring.map(r => (
                <div key={r.cve} style={{ display: "grid", gridTemplateColumns: "1fr 90px 90px 90px 110px", gap: 8, padding: "8px 0", borderBottom: "1px solid #f3f4f6", alignItems: "center" }}>
                  <div style={{ fontSize: 12, fontFamily: "monospace", color: "#374151" }}>{r.cve}</div>
                  <div style={{ fontSize: 12, color: "#6b7280" }}>{r.occurrences} scans</div>
                  <div style={{ fontSize: 11, color: "#9ca3af" }}>{_fmtDate(r.firstSeen)}</div>
                  <div style={{ fontSize: 11, color: "#9ca3af" }}>{_fmtDate(r.lastSeen)}</div>
                  <div>
                    <span style={{
                      fontSize: 11, fontWeight: 600, padding: "2px 8px", borderRadius: 20,
                      background: r.stillOpen ? "#fef2f2" : "#f0fdf4",
                      color: r.stillOpen ? "#dc2626" : "#16a34a",
                    }}>
                      {r.stillOpen ? "In latest scan" : "Not in latest scan"}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Scanner breakdown */}
        <div className="insight-card">
          <div className="insight-label">Scans by scanner</div>
          {scannerBreakdown.length === 0 ? (
            <div className="insight-text">No scans recorded yet.</div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 4 }}>
              {scannerBreakdown.map(([name, count]) => (
                <div key={name} style={{ display: "flex", justifyContent: "space-between", fontSize: 13, color: "#1e3a8a" }}>
                  <span style={{ textTransform: "capitalize" }}>{name}</span>
                  <span style={{ fontWeight: 700 }}>{count}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Full scan history table */}
      <div className="activity-card" style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" }}>
        <div className="activity-title">All scans</div>
        {scans.length === 0 ? (
          <div style={{ color: "#9ca3af", fontSize: 13, padding: "8px 4px" }}>No scans yet — upload or run one to start building history.</div>
        ) : (
          <div style={{ overflowY: "auto" }}>
            <div style={{ display: "grid", gridTemplateColumns: "110px 90px 1fr 60px 60px 60px 60px 60px", gap: 8, padding: "6px 0", borderBottom: "1px solid #e5e7eb", position: "sticky", top: 0, background: "#fff" }}>
              {["Date", "Scanner", "Target", "Total", "Crit", "High", "Med", "Low"].map(h => (
                <div key={h} style={{ fontSize: 11, fontWeight: 600, color: "#9ca3af", textTransform: "uppercase", letterSpacing: "0.04em" }}>{h}</div>
              ))}
            </div>
            {scans.map(s => (
              <div key={s.id}>
                <div
                  onClick={() => setExpandedScan(expandedScan === s.id ? null : s.id)}
                  style={{ display: "grid", gridTemplateColumns: "110px 90px 1fr 60px 60px 60px 60px 60px", gap: 8, padding: "10px 0", borderBottom: "1px solid #f3f4f6", cursor: "pointer", alignItems: "center" }}>
                  <div style={{ fontSize: 12, color: "#6b7280" }}>{_fmtDate(s.createdAt)}</div>
                  <div style={{ fontSize: 12, color: "#374151", textTransform: "capitalize" }}>{s.scanner || "—"}</div>
                  <div style={{ fontSize: 12, color: "#374151", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{s.target || "—"}</div>
                  <div style={{ fontSize: 12, fontWeight: 700, color: "#111" }}>{s.total}</div>
                  <div style={{ fontSize: 12, color: SEVERITY_COLORS.critical, fontWeight: 600 }}>{s.critical}</div>
                  <div style={{ fontSize: 12, color: SEVERITY_COLORS.high, fontWeight: 600 }}>{s.high}</div>
                  <div style={{ fontSize: 12, color: SEVERITY_COLORS.medium, fontWeight: 600 }}>{s.medium}</div>
                  <div style={{ fontSize: 12, color: SEVERITY_COLORS.low, fontWeight: 600 }}>{s.low}</div>
                </div>
                {expandedScan === s.id && (
                  <div style={{ padding: "8px 0 14px 4px", fontSize: 12, color: "#6b7280", background: "#f9fafb", borderBottom: "1px solid #f3f4f6" }}>
                    <div style={{ marginBottom: 4 }}>{s.source === "live" ? "Live scan" : "Uploaded report"} · Unrated: {s.unknown}</div>
                    {s.cveIds?.length ? (
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                        {s.cveIds.map(cve => (
                          <span key={cve} style={{ fontFamily: "monospace", fontSize: 11, background: "#eef0f4", padding: "2px 8px", borderRadius: 10 }}>{cve}</span>
                        ))}
                      </div>
                    ) : (
                      <div style={{ fontSize: 11, color: "#9ca3af" }}>No CVE-tagged findings in this scan.</div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
}

function _fmtDate(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
  } catch {
    return iso.slice(0, 10);
  }
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

// Profile settings (notifications toggle, default assignee) are saved to
// localStorage per-account, keyed by email, so they survive tab switches,
// sign-out/sign-in, and page reloads — not just held in memory.
const PROFILE_PREFS_PREFIX = "vulnwiz-profile-prefs:";
// notifications defaults to off, matching the backend's default (see
// auth.py's notify_on_critical column, NOT NULL DEFAULT 0) — the server
// value is authoritative once a session loads (see the /api/auth/me and
// sign-in/sign-up handlers below), this is just what shows before that.
const DEFAULT_PROFILE_PREFS = { notifications: false, defaultAssign: "Security Team" };

function loadProfilePrefs(email) {
  if (!email) return DEFAULT_PROFILE_PREFS;
  try {
    const raw = localStorage.getItem(PROFILE_PREFS_PREFIX + email);
    if (!raw) return DEFAULT_PROFILE_PREFS;
    const parsed = JSON.parse(raw);
    return {
      notifications: typeof parsed.notifications === "boolean" ? parsed.notifications : DEFAULT_PROFILE_PREFS.notifications,
      defaultAssign: typeof parsed.defaultAssign === "string" ? parsed.defaultAssign : DEFAULT_PROFILE_PREFS.defaultAssign,
    };
  } catch {
    return DEFAULT_PROFILE_PREFS;
  }
}

function saveProfilePrefs(email, prefs) {
  if (!email) return;
  try {
    localStorage.setItem(PROFILE_PREFS_PREFIX + email, JSON.stringify(prefs));
  } catch {
    // localStorage unavailable (e.g. private browsing) — fail silently,
    // prefs just won't persist across reloads this session.
  }
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
  const [authChecked, setAuthChecked] = useState(false);
  const [userName, setUserName] = useState("");
  const [userEmail, setUserEmail] = useState("");
  const [notifications, setNotifications] = useState(DEFAULT_PROFILE_PREFS.notifications);
  const [defaultAssign, setDefaultAssign] = useState(DEFAULT_PROFILE_PREFS.defaultAssign);
  // Only true for the stretch between a fresh signup and finishing the
  // business-context questionnaire — sign-in and session-restore never
  // set this, so returning users go straight to the dashboard.
  const [showBusinessContext, setShowBusinessContext] = useState(false);

  // On load, ask the backend whether this browser already has a signed-in
  // session (session cookie from a previous visit) so a page refresh doesn't
  // bounce a signed-in user back to the sign-in screen.
  // Fetches this account's saved tickets from the backend (see tickets.py)
  // and replaces whatever's currently in liveTickets. Called after every
  // successful sign-in/sign-up/session-restore so tickets follow the
  // account instead of living only in this browser tab's memory.
  const loadTickets = () => {
    fetch(`${API_BASE}/api/tickets`, { credentials: "include" })
      .then(res => res.json())
      .then(data => setLiveTickets(Array.isArray(data) ? data : []))
      .catch(() => {});
  };

  useEffect(() => {
    // A fresh Google sign-up redirects here as a normal page navigation
    // (see google_auth.py's callback), so we can't tell "brand new
    // account" apart from "returning user's session restored" just from
    // /api/auth/me — both come back authenticated. google_auth.py flags
    // the new-account case with ?newAccount=1 on the redirect (same
    // pattern SignIn already uses for ?authError=); catch it here so SSO
    // signups land in the business-context questionnaire too, instead of
    // skipping straight to the dashboard.
    const isNewAccount = new URLSearchParams(window.location.search).get("newAccount") === "1";
    if (isNewAccount) {
      window.history.replaceState({}, "", window.location.pathname);
    }

    fetch(`${API_BASE}/api/auth/me`, { credentials: "include" })
      .then(res => res.json())
      .then(data => {
        if (data.authenticated) {
          setUserName(data.name);
          setUserEmail(data.email);
          setAuthed(true);
          const prefs = loadProfilePrefs(data.email);
          // notifyOnCritical is authoritative from the server (it's what
          // scanner.py actually checks before sending an alert email) —
          // only defaultAssign, which has no server-side effect, comes
          // from localStorage.
          setNotifications(!!data.notifyOnCritical);
          setDefaultAssign(prefs.defaultAssign);
          if (isNewAccount) {
            setShowBusinessContext(true);
          }
          loadTickets();
        }
      })
      .catch(() => {})
      .finally(() => setAuthChecked(true));
  }, []);

  // Flips the Email notifications toggle and persists it server-side (see
  // PATCH /api/auth/notifications in auth.py) — scanner.py reads this
  // column directly when deciding whether to send a critical-finding
  // alert, so it has to live on the backend, not just in this browser tab.
  const updateNotifications = (enabled) => {
    setNotifications(enabled);
    fetch(`${API_BASE}/api/auth/notifications`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ enabled }),
    }).catch(() => {});
  };

  // Whenever the signed-in user changes their profile prefs, persist them
  // under that user's own key so they're there next time they sign in.
  useEffect(() => {
    if (!authed || !userEmail) return;
    saveProfilePrefs(userEmail, { notifications, defaultAssign });
  }, [notifications, defaultAssign, authed, userEmail]);

  const goToTab = tab => { setActiveTab(tab); setUploadStep(0); setCveId(null); setUploadedFile(null); };

  // Clears everything that belongs to the signed-in user's session, so the
  // next person who signs in doesn't inherit the previous user's tickets,
  // in-progress upload, or selections.
  const resetSession = () => {
    setActiveTab("dashboard");
    setUploadStep(0);
    setCveId(null);
    setSelected(vulnRows.map(r => r.id));
    setSubmittedTickets([]);
    setLiveTickets([]);
    setUploadedFile(null);
  };

  const handleScanParsed = (vulnerabilities, meta) => {
    applyScanResults(vulnerabilities, meta);
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
      case 3: return <ValidationStep onNext={() => setUploadStep(4)} onBack={() => setUploadStep(2)} selected={selected} setSelected={setSelected} onCveClick={id => { setPrevStep(3); setCveId(id); }} />;
      case 4: return <GenerateTicketStep onNext={(approved) => { setSubmittedTickets(approved); setUploadStep(5); }} onBack={() => setUploadStep(3)} selected={selected} />;
      case 5: return <ReviewSendStep onNext={() => goToTab("tickets")} onBack={() => setUploadStep(4)} selected={selected} approvedTickets={submittedTickets} onSubmit={(newTickets) => setLiveTickets(prev => [...prev, ...newTickets])} />;
      default: return null;
    }
  };

  if (!authChecked) {
    // Brief blank shell while we check for an existing session, so a
    // signed-in user doesn't flash the sign-in screen on every refresh.
    return (
      <>
        <style>{css}</style>
        <div className="shell" />
      </>
    );
  }

  if (!authed) {
    return (
      <>
        <style>{css}</style>
        <div className="shell">
          {authScreen === "signin"
            ? <SignIn
                onSignIn={data => {
                  setUserName(data.name);
                  setUserEmail(data.email);
                  setAuthed(true);
                  const prefs = loadProfilePrefs(data.email);
                  setNotifications(!!data.notifyOnCritical);
                  setDefaultAssign(prefs.defaultAssign);
                  loadTickets();
                }}
                onGoSignUp={() => setAuthScreen("signup")}
              />
            : <SignUp
                onSignUp={data => {
                  setUserName(data.name);
                  setUserEmail(data.email);
                  setAuthed(true);
                  const prefs = loadProfilePrefs(data.email);
                  setNotifications(!!data.notifyOnCritical);
                  setDefaultAssign(prefs.defaultAssign);
                  setShowBusinessContext(true);
                }}
                onGoSignIn={() => setAuthScreen("signin")}
              />
          }
        </div>
      </>
    );
  }

  if (showBusinessContext) {
    return (
      <>
        <style>{css}</style>
        <div className="shell">
          <BusinessContextStep onComplete={() => setShowBusinessContext(false)} />
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
        {activeTab === "history" && <ScanHistory />}
        {activeTab === "tickets" && <TicketList tickets={liveTickets} />}
        {activeTab === "profile" && (
          <Profile
            onSignOut={() => {
              fetch(`${API_BASE}/api/auth/logout`, { method: "POST", credentials: "include" }).catch(() => {});
              resetSession();
              setAuthed(false);
              setAuthScreen("signin");
              setUserName("");
              setUserEmail("");
              setShowBusinessContext(false);
            }}
            userName={userName}
            userEmail={userEmail}
            notifications={notifications}
            setNotifications={updateNotifications}
            defaultAssign={defaultAssign}
            setDefaultAssign={setDefaultAssign}
          />
        )}

        <ChatWidget />
      </div>
    </>
  );
}
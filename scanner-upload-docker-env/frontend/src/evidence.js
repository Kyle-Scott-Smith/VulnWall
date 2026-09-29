/*
 * Evidence links — where a finding's claims can actually be checked.
 *
 * These are plain links to public records. They do NOT assert that the app
 * has verified anything against them; earlier versions of the UI showed
 * green "verified against NVD / MITRE" ticks with no check behind them,
 * which testers read as fake. Now we just point at the source and let the
 * person look.
 */

const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;

export function isCveId(id) {
  return typeof id === "string" && CVE_RE.test(id.trim());
}

// Scanner references arrive as an array (Trivy) or, from some Tenable
// exports, a newline/space separated string. Accept both, keep only
// http(s) URLs, drop duplicates.
export function normalizeReferences(references) {
  const raw = Array.isArray(references)
    ? references
    : typeof references === "string"
      ? references.split(/[\s,]+/)
      : [];
  const seen = new Set();
  const out = [];
  for (const r of raw) {
    if (typeof r !== "string") continue;
    const url = r.trim();
    if (!/^https?:\/\//i.test(url) || seen.has(url)) continue;
    seen.add(url);
    out.push(url);
  }
  return out;
}

function hostLabel(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

// Returns { records, references }.
//  records    - public CVE records (only for real CVE ids; non-CVE ids like
//               Tenable "PLUGIN-1234" get none rather than a dead link)
//  references - scanner-supplied advisory/vendor links, labelled by host
export function evidenceLinks(cveId, references, maxReferences = 5) {
  const records = [];
  if (isCveId(cveId)) {
    const id = cveId.trim().toUpperCase();
    records.push(
      { label: "NVD record", url: `https://nvd.nist.gov/vuln/detail/${id}` },
      { label: "CVE.org record", url: `https://www.cve.org/CVERecord?id=${id}` },
    );
  }
  const refs = normalizeReferences(references)
    .slice(0, maxReferences)
    .map(url => ({ label: hostLabel(url), url }));
  return { records, references: refs };
}

// "Checked with Jira at 14:32" style text from an ISO timestamp.
export function formatSyncedAt(iso, now = new Date()) {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  const mins = Math.round((now - d) / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  return d.toLocaleString(undefined, { hour: "2-digit", minute: "2-digit", day: "numeric", month: "short" });
}

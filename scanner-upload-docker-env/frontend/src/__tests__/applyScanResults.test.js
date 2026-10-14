// Tests for applyScanResults() in App.jsx — it turns the raw vulnerability
// list from the backend into vulnRows/cveDetails/allRisks/validationRows,
// the state every wizard screen renders from. A bug here breaks the whole
// AI Analysis / Select / Validation flow silently, since nothing else
// re-derives this data independently.
import { describe, expect, it } from "vitest";
import { applyScanResults, validationReasons, cveDetails, vulnRows, allRisks, validationRows, lastVulnerabilities, lastScanMeta } from "../App.jsx";

describe("applyScanResults", () => {
  it("defaults missing fields (severity, cvss, asset)", () => {
    applyScanResults([{ cve: "CVE-2024-0001" }]);
    expect(vulnRows).toHaveLength(1);
    expect(vulnRows[0]).toMatchObject({
      id: "CVE-2024-0001",
      title: "CVE-2024-0001",
      severity: "Unknown",
      cvss: 0,
      asset: "unknown",
      businessPriorityScore: null,
    });
  });

  it("falls back asset to package when no asset given", () => {
    applyScanResults([{ cve: "CVE-2024-0002", package: "openssl" }]);
    expect(vulnRows[0].asset).toBe("openssl");
  });

  it("carries a real business_priority_score through when the backend supplies one", () => {
    applyScanResults([{ cve: "CVE-2024-0003", cvss: 9.0, business_priority_score: 15.75 }]);
    expect(vulnRows[0].businessPriorityScore).toBe(15.75);
    expect(allRisks[0].businessPriorityScore).toBe(15.75);
  });

  it("ignores a non-numeric business_priority_score instead of carrying it through", () => {
    applyScanResults([{ cve: "CVE-2024-0004", business_priority_score: "not-a-number" }]);
    expect(vulnRows[0].businessPriorityScore).toBeNull();
  });

  it("uses heuristic placeholder fixes/why when no AI analysis has run yet", () => {
    applyScanResults([{
      cve: "CVE-2024-0005",
      package: "libfoo",
      installedVersion: "1.2.3",
      description: "A thing is broken.",
      cvss: 7.0,
    }]);
    const d = cveDetails["CVE-2024-0005"];
    expect(d.aiGenerated).toBe(false);
    expect(d.why).toBe("A thing is broken.");
    expect(d.fixes[0]).toContain("Upgrade libfoo beyond the installed version (1.2.3)");
    // No AI ran, so there is no confidence. It used to be invented (95/65).
    expect(d.confidence).toBeNull();
  });

  it("uses the real AI fields when ai_generated is present, even if false (template fallback)", () => {
    applyScanResults([{
      cve: "CVE-2024-0006",
      why: "Real analysis text.",
      business_impact: "Real business impact text.",
      fixes: ["Do the real fix"],
      confidence: 30,
      ai_generated: false, // template fallback still counts as "has an AI result"
    }]);
    const d = cveDetails["CVE-2024-0006"];
    expect(d.aiGenerated).toBe(false);
    expect(d.why).toBe("Real analysis text.");
    expect(d.businessImpact).toBe("Real business impact text.");
    expect(d.fixes).toEqual(["Do the real fix"]);
    expect(d.confidence).toBe(30);
  });

  it("falls back fixes to a default when ai_generated is present but fixes is empty", () => {
    applyScanResults([{ cve: "CVE-2024-0007", ai_generated: true, fixes: [] }]);
    expect(cveDetails["CVE-2024-0007"].fixes).toEqual([
      "Review the vendor advisory and apply the recommended patch.",
    ]);
  });

  it("flags entries missing cvss or description as Needs Review pre-analysis", () => {
    applyScanResults([
      { cve: "CVE-2024-0008", cvss: 5.0, description: "complete" },
      { cve: "CVE-2024-0009", description: "missing cvss" },
      { cve: "CVE-2024-0010", cvss: 5.0 }, // missing description
    ]);
    const byId = Object.fromEntries(validationRows.map(r => [r.id, r.status]));
    expect(byId["CVE-2024-0008"]).toBe("No flags");
    expect(byId["CVE-2024-0009"]).toBe("Needs Review");
    expect(byId["CVE-2024-0010"]).toBe("Needs Review");
  });

  it("flags low-confidence AI results as Needs Review even though ai_generated is present", () => {
    applyScanResults([
      { cve: "CVE-2024-0011", ai_generated: true, confidence: 90 },
      { cve: "CVE-2024-0012", ai_generated: true, confidence: 40 },
      { cve: "CVE-2024-0013", ai_generated: false, confidence: 90 }, // template fallback, not real AI
    ]);
    const byId = Object.fromEntries(validationRows.map(r => [r.id, r.status]));
    expect(byId["CVE-2024-0011"]).toBe("No flags");
    expect(byId["CVE-2024-0012"]).toBe("Needs Review");
    expect(byId["CVE-2024-0013"]).toBe("Needs Review");
  });

  it("never invents a confidence: AI result without one stays null, not 50", () => {
    applyScanResults([{ cve: "CVE-2024-0020", ai_generated: true, why: "x" }]);
    expect(cveDetails["CVE-2024-0020"].confidence).toBeNull();
  });

  it("gives a plain-language reason for every flag, and none when nothing is flagged", () => {
    applyScanResults([
      { cve: "CVE-2024-0021", cvss: 5.0, description: "ok" },
      { cve: "CVE-2024-0022", description: "no score" },
      { cve: "CVE-2024-0023", ai_generated: true, confidence: 40 },
    ]);
    const byId = Object.fromEntries(validationRows.map(r => [r.id, r]));
    expect(byId["CVE-2024-0021"].reasons).toEqual([]);
    expect(byId["CVE-2024-0022"].reasons).toEqual(["The scanner gave no CVSS score."]);
    expect(byId["CVE-2024-0023"].reasons[0]).toContain("low confidence");
    expect(byId["CVE-2024-0023"].reasons[0]).toContain("40%");
  });

  it("uses title as the id when no cve is present, and only the title (not id) falls back when neither is", () => {
    applyScanResults([{ title: "Unmapped finding" }, {}]);
    expect(vulnRows[0].id).toBe("Unmapped finding");
    // Neither cve nor title given — id itself has no fallback in the code,
    // only title does (`v.title || v.cve || "Untitled finding"`).
    expect(vulnRows[1].id).toBeUndefined();
    expect(vulnRows[1].title).toBe("Untitled finding");
  });

  it("preserves the backend's ordering in allRisks rather than re-sorting", () => {
    applyScanResults([
      { cve: "CVE-2024-0020", cvss: 1.0 },
      { cve: "CVE-2024-0021", cvss: 9.0 },
    ]);
    expect(allRisks.map(r => r.id)).toEqual(["CVE-2024-0020", "CVE-2024-0021"]);
  });

  it("records lastVulnerabilities as exactly the list passed in", () => {
    const list = [{ cve: "CVE-2024-0030", cvss: 3.3 }];
    applyScanResults(list);
    expect(lastVulnerabilities).toBe(list);
  });

  it("ignores a non-array input instead of throwing", () => {
    expect(() => applyScanResults(null)).not.toThrow();
    expect(vulnRows).toEqual([]);
    expect(allRisks).toEqual([]);
  });

  it("sets lastScanMeta when meta is passed, and leaves it alone when meta is omitted", () => {
    applyScanResults([{ cve: "CVE-2024-0040" }], { scanner: "trivy", source: "upload", target: "image:latest" });
    expect(lastScanMeta).toEqual({ scanner: "trivy", source: "upload", target: "image:latest" });

    // Second call (e.g. the AI-analysis re-apply) omits meta — should not wipe it out.
    applyScanResults([{ cve: "CVE-2024-0040", ai_generated: true }]);
    expect(lastScanMeta).toEqual({ scanner: "trivy", source: "upload", target: "image:latest" });
  });
});

describe("validationReasons", () => {
  it("reports every missing-data reason before AI has run", () => {
    expect(validationReasons({})).toEqual(["The scanner gave no CVSS score.", "The scanner gave no description."]);
  });
  it("flags a template fallback", () => {
    expect(validationReasons({ ai_generated: false })[0]).toContain("generic template");
  });
  it("does not flag a real AI result at or above the threshold", () => {
    expect(validationReasons({ ai_generated: true, confidence: 60 })).toEqual([]);
    expect(validationReasons({ ai_generated: true })).toEqual([]);
  });
  it("can give both a template and low-confidence reason", () => {
    expect(validationReasons({ ai_generated: false, confidence: 10 })).toHaveLength(2);
  });
});

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

// ---------------------------------------------------------------------------
// Added coverage
// ---------------------------------------------------------------------------
describe("applyScanResults — added edge cases", () => {
  it("uses the AI confidence verbatim when present", () => {
    applyScanResults([{ cve: "CVE-2024-5002", ai_generated: true, why: "w", fixes: ["f"], confidence: 88 }]);
    expect(cveDetails["CVE-2024-5002"].confidence).toBe(88);
  });

  it("keeps a real confidence of 0 — zero is an answer, not 'missing' — and flags it as low", () => {
    applyScanResults([{ cve: "CVE-2024-5015", ai_generated: true, why: "w", fixes: ["f"], confidence: 0 }]);
    expect(cveDetails["CVE-2024-5015"].confidence).toBe(0);
    expect(validationRows[0].status).toBe("Needs Review");
    expect(validationRows[0].reasons[0]).toContain("0%");
  });

  it("treats a non-numeric AI confidence as missing instead of passing it through", () => {
    applyScanResults([
      { cve: "CVE-2024-5016", ai_generated: true, confidence: "90" },
      { cve: "CVE-2024-5017", ai_generated: true, confidence: NaN },
    ]);
    expect(cveDetails["CVE-2024-5016"].confidence).toBeNull();
    expect(cveDetails["CVE-2024-5017"].confidence).toBeNull();
  });

  it("explains a missing AI 'why' instead of showing nothing", () => {
    applyScanResults([{ cve: "CVE-2024-5003", ai_generated: true }]);
    expect(cveDetails["CVE-2024-5003"].why).toMatch(/No explanation/);
    expect(cveDetails["CVE-2024-5003"].businessImpact).toBe("");
  });

  it("exposes business impact, tier and the aiGenerated flag from the AI result", () => {
    applyScanResults([{ cve: "CVE-2024-5004", ai_generated: true, why: "w", business_impact: "Patient data", fixes: ["f"], priority_tier: "P1" }]);
    expect(cveDetails["CVE-2024-5004"]).toMatchObject({ businessImpact: "Patient data", priorityTier: "P1", aiGenerated: true });
  });

  it("reports aiGenerated false and no tier before analysis has run", () => {
    applyScanResults([{ cve: "CVE-2024-5005" }]);
    expect(cveDetails["CVE-2024-5005"]).toMatchObject({ aiGenerated: false, priorityTier: null });
  });

  it("builds heuristic fixes from the package and installed version", () => {
    applyScanResults([{ cve: "CVE-2024-5006", package: "openssl", installedVersion: "3.0.1" }]);
    const fixes = cveDetails["CVE-2024-5006"].fixes;
    expect(fixes[0]).toBe("Upgrade openssl beyond the installed version (3.0.1)");
    expect(fixes).toHaveLength(3);
  });

  it("builds a shorter heuristic fix when only the package is known", () => {
    applyScanResults([{ cve: "CVE-2024-5007", package: "zlib" }]);
    expect(cveDetails["CVE-2024-5007"].fixes[0]).toBe("Upgrade zlib to a patched version");
  });

  it("still gives two generic fixes when no package is known", () => {
    applyScanResults([{ cve: "CVE-2024-5008" }]);
    expect(cveDetails["CVE-2024-5008"].fixes).toHaveLength(2);
  });

  it("has no confidence before analysis, however complete the scanner data is", () => {
    applyScanResults([
      { cve: "CVE-2024-5009", cvss: 7, description: "d" },
      { cve: "CVE-2024-5010", cvss: 7 },
      { cve: "CVE-2024-5011", description: "d" },
    ]);
    expect([cveDetails["CVE-2024-5009"].confidence, cveDetails["CVE-2024-5010"].confidence, cveDetails["CVE-2024-5011"].confidence])
      .toEqual([null, null, null]);
  });

  it("marks a fully described pre-analysis finding 'No flags' with no reasons", () => {
    applyScanResults([{ cve: "CVE-2024-5012", cvss: 5, description: "d", title: "t" }]);
    expect(validationRows[0]).toMatchObject({ id: "CVE-2024-5012", status: "No flags", reasons: [], desc: "t" });
  });

  it("marks a template-fallback AI result (ai_generated false) Needs Review", () => {
    applyScanResults([{ cve: "CVE-2024-5013", ai_generated: false, confidence: 99 }]);
    expect(validationRows[0].status).toBe("Needs Review");
  });

  it("raises no flag for an AI result that carries no confidence (a missing one is not 'low')", () => {
    applyScanResults([{ cve: "CVE-2024-5014", ai_generated: true }]);
    expect(validationRows[0]).toMatchObject({ status: "No flags", reasons: [] });
  });

  it("clears the flag at exactly 60% confidence but not at 59%", () => {
    applyScanResults([{ cve: "A", ai_generated: true, confidence: 60 }, { cve: "B", ai_generated: true, confidence: 59 }]);
    expect(validationRows.map(r => r.status)).toEqual(["No flags", "Needs Review"]);
  });

  it("keeps references as an array or string, and drops anything else", () => {
    applyScanResults([
      { cve: "R1", references: ["https://a.example"] },
      { cve: "R2", references: "https://b.example https://c.example" },
      { cve: "R3", references: 42 },
      { cve: "R4" },
    ]);
    expect(cveDetails.R1.references).toEqual(["https://a.example"]);
    expect(cveDetails.R2.references).toBe("https://b.example https://c.example");
    expect(cveDetails.R3.references).toEqual([]);
    expect(cveDetails.R4.references).toEqual([]);
  });

  it("replaces the previous scan's rows entirely", () => {
    applyScanResults([{ cve: "OLD-1" }, { cve: "OLD-2" }]);
    applyScanResults([{ cve: "NEW-1" }]);
    expect(vulnRows.map(r => r.id)).toEqual(["NEW-1"]);
    expect(Object.keys(cveDetails)).toEqual(["NEW-1"]);
    expect(allRisks).toHaveLength(1);
    expect(validationRows).toHaveLength(1);
  });

  it("an empty list clears every derived structure", () => {
    applyScanResults([{ cve: "X" }]);
    applyScanResults([]);
    expect(vulnRows).toEqual([]);
    expect(cveDetails).toEqual({});
    expect(allRisks).toEqual([]);
    expect(validationRows).toEqual([]);
  });

  it("copes with a non-numeric cvss by treating it as 0", () => {
    applyScanResults([{ cve: "CVE-2024-5020", cvss: "9.8" }]);
    expect(vulnRows[0].cvss).toBe(0);
    expect(cveDetails["CVE-2024-5020"].cvss).toBe(0);
  });
});

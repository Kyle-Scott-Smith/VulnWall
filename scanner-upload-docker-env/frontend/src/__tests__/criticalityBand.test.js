// Tests for criticalityBand() in App.jsx — maps the raw business_priority_score
// to a plain-English band.
//
// IMPORTANT, discovered while writing these tests: ceiling is computed as
// (score/cvss)*10, and ratio as score/ceiling. Substituting shows this
// ALWAYS reduces to exactly cvss/10, for any score — the business-context
// multiplier baked into `score` cancels out algebraically:
//   ratio = score / ((score/cvss)*10) = (score*cvss) / (score*10) = cvss/10
// Since compute_business_priority_score scales every finding in a given
// org's scan by the SAME constant multiplier, this means the band shown is
// currently indistinguishable from a plain-CVSS band — business context
// changes the tooltip number but never the label. Tests below document
// today's actual behavior (including this quirk); see chat for the
// follow-up discussion on whether it should be fixed.
import { describe, expect, it } from "vitest";
import { criticalityBand } from "../App.jsx";

describe("criticalityBand", () => {
  it("bands a plain CVSS score with no business multiplier (score === cvss)", () => {
    expect(criticalityBand(9.8, 9.8).label).toBe("High criticality");
    expect(criticalityBand(5.0, 5.0).label).toBe("Medium criticality");
    expect(criticalityBand(2.0, 2.0).label).toBe("Low criticality");
  });

  it("REGRESSION: the business multiplier has no effect on the band, only cvss does", () => {
    // Same cvss, wildly different business multipliers baked into score —
    // the band comes out identical every time. If this test ever starts
    // failing because the band DOES change with the multiplier, that's a
    // sign the underlying formula was fixed, and this test (plus the
    // comment above) should be updated/removed.
    const noMultiplier = criticalityBand(9.0, 9.0); // multiplier 1x
    const bigMultiplier = criticalityBand(57.375, 9.0); // multiplier 6.375x
    expect(bigMultiplier.label).toBe(noMultiplier.label);
    expect(bigMultiplier.label).toBe("High criticality");
  });

  it("sits right at the High/Medium boundary (cvss/10 ratio of 0.7)", () => {
    expect(criticalityBand(7.0, 7.0).label).toBe("High criticality");
    expect(criticalityBand(6.99, 6.99).label).toBe("Medium criticality");
  });

  it("sits right at the Medium/Low boundary (cvss/10 ratio of 0.4)", () => {
    expect(criticalityBand(4.0, 4.0).label).toBe("Medium criticality");
    expect(criticalityBand(3.99, 3.99).label).toBe("Low criticality");
  });

  it("falls back to a ceiling of 10 when cvss is 0 or missing, without throwing", () => {
    expect(() => criticalityBand(5.0, 0)).not.toThrow();
    expect(criticalityBand(5.0, 0).label).toBe("Medium criticality");
  });

  it("never returns undefined for a score of 0", () => {
    expect(criticalityBand(0, 10.0).label).toBe("Low criticality");
  });

  it("returns a color alongside the label", () => {
    const band = criticalityBand(9.8, 9.8);
    expect(band.color).toMatch(/^#/);
  });
});

import { describe, it, expect } from "vitest";
import { hasConfidence, formatConfidence, isLowConfidence, LOW_CONFIDENCE_THRESHOLD } from "../confidence";

describe("confidence helpers", () => {
  it("treats only real numbers as a confidence", () => {
    expect(hasConfidence(0)).toBe(true);
    expect(hasConfidence(85)).toBe(true);
    for (const v of [null, undefined, "90", NaN]) expect(hasConfidence(v)).toBe(false);
  });

  it("shows 'Not assessed' instead of a number when there isn't one", () => {
    expect(formatConfidence(72)).toBe("72%");
    expect(formatConfidence(null)).toBe("Not assessed");
    expect(formatConfidence(undefined)).toBe("Not assessed");
  });

  it("flags only a real number below 60 — a missing one is not 'low'", () => {
    expect(isLowConfidence(59)).toBe(true);
    expect(isLowConfidence(60)).toBe(false);
    expect(isLowConfidence(null)).toBe(false); // null < 60 is true in JS; must not be flagged orange
  });
});

// ---------------------------------------------------------------------------
// Added coverage
// ---------------------------------------------------------------------------
describe("confidence helpers — edge cases", () => {
  it("does not count Infinity as a confidence", () => {
    expect(hasConfidence(Infinity)).toBe(false);
    expect(hasConfidence(-Infinity)).toBe(false);
  });

  it("shows a real zero as 0%, not 'Not assessed'", () => {
    expect(formatConfidence(0)).toBe("0%");
  });

  it("flags a real zero as low (zero is an answer, not a missing value)", () => {
    expect(isLowConfidence(0)).toBe(true);
  });

  it("does not flag non-numbers, whatever they coerce to", () => {
    for (const v of ["10", "", {}, [], false, NaN]) expect(isLowConfidence(v)).toBe(false);
  });

  it("uses a threshold of 60 — the number the Validation step and the ticket screens share", () => {
    expect(LOW_CONFIDENCE_THRESHOLD).toBe(60);
  });
});

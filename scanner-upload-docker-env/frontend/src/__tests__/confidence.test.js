import { describe, it, expect } from "vitest";
import { hasConfidence, formatConfidence, isLowConfidence } from "../confidence";

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

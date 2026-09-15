// Tests for splitSummary() in App.jsx — splits AI-generated prose into a
// lead sentence (shown by default) and the remainder (behind "Read more").
import { describe, expect, it } from "vitest";
import { splitSummary } from "../App.jsx";

describe("splitSummary", () => {
  it("returns empty summary and rest for empty/undefined input", () => {
    expect(splitSummary("")).toEqual({ summary: "", rest: "" });
    expect(splitSummary(undefined)).toEqual({ summary: "", rest: "" });
  });

  it("splits a multi-sentence paragraph into lead sentence + rest", () => {
    const { summary, rest } = splitSummary("First sentence here. Second sentence follows. Third one too.");
    expect(summary).toBe("First sentence here.");
    expect(rest).toBe("Second sentence follows. Third one too.");
  });

  it("treats a single-sentence string as summary-only, with no rest", () => {
    const { summary, rest } = splitSummary("Just one sentence here.");
    expect(summary).toBe("Just one sentence here.");
    expect(rest).toBe("");
  });

  it("handles ! and ? as valid terminators, not just .", () => {
    expect(splitSummary("Is this exploitable? Yes, definitely.")).toEqual({
      summary: "Is this exploitable?",
      rest: "Yes, definitely.",
    });
    expect(splitSummary("Patch immediately! Do not delay.")).toEqual({
      summary: "Patch immediately!",
      rest: "Do not delay.",
    });
  });

  it("treats text with no terminating punctuation as summary-only", () => {
    const { summary, rest } = splitSummary("no terminator on this one");
    expect(summary).toBe("no terminator on this one");
    expect(rest).toBe("");
  });

  it("trims surrounding whitespace on both parts", () => {
    const { summary, rest } = splitSummary("  Leading space sentence.   Trailing rest.   ");
    expect(summary).toBe("Leading space sentence.");
    expect(rest).toBe("Trailing rest.");
  });
});

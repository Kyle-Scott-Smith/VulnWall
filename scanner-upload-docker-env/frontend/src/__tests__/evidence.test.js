import { describe, it, expect } from "vitest";
import { evidenceLinks, isCveId, normalizeReferences, formatSyncedAt } from "../evidence";

describe("evidenceLinks", () => {
  it("builds NVD and CVE.org links for a real CVE id", () => {
    const { records } = evidenceLinks("cve-2024-3094", []);
    expect(records.map(r => r.url)).toEqual([
      "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
      "https://www.cve.org/CVERecord?id=CVE-2024-3094",
    ]);
  });

  it("gives no record links for non-CVE ids (e.g. Tenable plugin ids)", () => {
    expect(evidenceLinks("PLUGIN-12345", []).records).toEqual([]);
    expect(evidenceLinks(undefined, []).records).toEqual([]);
  });

  it("labels scanner references by host, dedupes, caps the count", () => {
    const refs = ["https://www.openssl.org/news/a", "https://www.openssl.org/news/a", "https://github.com/x/y"];
    const { references } = evidenceLinks("CVE-2024-1111", refs, 5);
    expect(references).toEqual([
      { label: "openssl.org", url: "https://www.openssl.org/news/a" },
      { label: "github.com", url: "https://github.com/x/y" },
    ]);
    expect(evidenceLinks("CVE-2024-1111", ["https://a.com/1", "https://b.com/2", "https://c.com/3"], 2).references).toHaveLength(2);
  });
});

describe("normalizeReferences", () => {
  it("accepts whitespace-separated strings and rejects non-http(s) schemes", () => {
    expect(normalizeReferences("https://a.com/1\nhttp://b.com/2 javascript:alert(1)")).toEqual(["https://a.com/1", "http://b.com/2"]);
  });

  it("returns [] for junk input", () => {
    expect(normalizeReferences(null)).toEqual([]);
    expect(normalizeReferences([1, {}, ""])).toEqual([]);
  });
});

describe("isCveId", () => {
  it("matches CVE format only", () => {
    expect(isCveId("CVE-2026-33845")).toBe(true);
    expect(isCveId("CVE-26-1")).toBe(false);
  });
});

describe("formatSyncedAt", () => {
  const now = new Date("2026-09-29T10:00:00Z");
  it("handles null, invalid and recent timestamps", () => {
    expect(formatSyncedAt(null, now)).toBeNull();
    expect(formatSyncedAt("nope", now)).toBeNull();
    expect(formatSyncedAt("2026-09-29T09:59:40Z", now)).toBe("just now");
    expect(formatSyncedAt("2026-09-29T09:45:00Z", now)).toBe("15 min ago");
  });
});

// ---------------------------------------------------------------------------
// Added coverage
// ---------------------------------------------------------------------------
describe("isCveId — edge cases", () => {
  it("accepts any case and surrounding whitespace", () => {
    expect(isCveId("  cve-2024-12345  ")).toBe(true);
  });

  it("needs a four-digit year and at least four sequence digits", () => {
    expect(isCveId("CVE-2024-123")).toBe(false);
    expect(isCveId("CVE-24-1234")).toBe(false);
    expect(isCveId("CVE-2024-1234567")).toBe(true);
  });

  it("rejects non-strings and lookalikes", () => {
    for (const bad of [null, undefined, 123, {}, [], "PLUGIN-1234", "CVE 2024 1234", "xCVE-2024-1234", "CVE-2024-1234x"]) {
      expect(isCveId(bad)).toBe(false);
    }
  });
});

describe("normalizeReferences — edge cases", () => {
  it("splits on commas as well as whitespace", () => {
    expect(normalizeReferences("https://a.com/1,https://b.com/2")).toEqual(["https://a.com/1", "https://b.com/2"]);
  });

  it("accepts an upper-case scheme", () => {
    expect(normalizeReferences(["HTTPS://A.COM/x"])).toEqual(["HTTPS://A.COM/x"]);
  });

  it("rejects javascript:, data: and protocol-relative links", () => {
    expect(normalizeReferences(["javascript:alert(1)", "data:text/html,hi", "//evil.example/x", "ftp://x.example"])).toEqual([]);
  });

  it("trims whitespace around each entry", () => {
    expect(normalizeReferences(["  https://a.com/1  "])).toEqual(["https://a.com/1"]);
  });

  it("returns [] for numbers, objects and undefined", () => {
    expect(normalizeReferences(42)).toEqual([]);
    expect(normalizeReferences({})).toEqual([]);
    expect(normalizeReferences(undefined)).toEqual([]);
  });
});

describe("evidenceLinks — edge cases", () => {
  it("returns empty groups for nothing at all", () => {
    expect(evidenceLinks(undefined, undefined)).toEqual({ records: [], references: [] });
  });

  it("upper-cases and trims the CVE id in record links", () => {
    expect(evidenceLinks("  cve-2024-0001 ", []).records[0].url).toBe("https://nvd.nist.gov/vuln/detail/CVE-2024-0001");
  });

  it("labels each record link", () => {
    expect(evidenceLinks("CVE-2024-0001", []).records.map(r => r.label)).toEqual(["NVD record", "CVE.org record"]);
  });

  it("defaults to at most five references", () => {
    const refs = Array.from({ length: 9 }, (_, i) => `https://site${i}.example/p`);
    expect(evidenceLinks("CVE-2024-0001", refs).references).toHaveLength(5);
  });

  it("allows zero references to be requested", () => {
    expect(evidenceLinks("CVE-2024-0001", ["https://a.com/1"], 0).references).toEqual([]);
  });

  it("strips a leading www. from the label but keeps other subdomains", () => {
    const { references } = evidenceLinks("CVE-2024-0001", ["https://www.a.com/1", "https://docs.b.com/2"]);
    expect(references.map(r => r.label)).toEqual(["a.com", "docs.b.com"]);
  });

  it("still returns references for findings that have no CVE id", () => {
    const { records, references } = evidenceLinks("PLUGIN-9", ["https://vendor.example/advisory"]);
    expect(records).toEqual([]);
    expect(references).toHaveLength(1);
  });
});

describe("formatSyncedAt — edge cases", () => {
  const now = new Date("2026-05-01T12:00:00Z");
  it("says 'just now' for under a minute, including a few seconds in the future", () => {
    expect(formatSyncedAt("2026-05-01T11:59:40Z", now)).toBe("just now");
    expect(formatSyncedAt("2026-05-01T12:00:20Z", now)).toBe("just now");
  });

  it("counts minutes up to the hour", () => {
    expect(formatSyncedAt("2026-05-01T11:55:00Z", now)).toBe("5 min ago");
    expect(formatSyncedAt("2026-05-01T11:01:00Z", now)).toBe("59 min ago");
  });

  it("switches to a calendar time from an hour onward", () => {
    const out = formatSyncedAt("2026-05-01T10:00:00Z", now);
    expect(out).not.toMatch(/min ago|just now/);
    expect(out.length).toBeGreaterThan(0);
  });

  it("returns null for missing or unparseable input", () => {
    expect(formatSyncedAt(null, now)).toBeNull();
    expect(formatSyncedAt("", now)).toBeNull();
    expect(formatSyncedAt("not a date", now)).toBeNull();
  });
});

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

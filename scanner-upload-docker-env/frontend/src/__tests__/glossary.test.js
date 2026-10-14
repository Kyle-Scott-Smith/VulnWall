// Integrity checks for the hover-explanations. An unknown glossary key
// doesn't crash — <Term> just renders plain text — so a typo in App.jsx
// would silently lose a tooltip. These tests turn that silent failure into a
// red test by cross-checking every key used in App.jsx against Glossary.jsx.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { GLOSSARY } from "../Glossary";

const here = dirname(fileURLToPath(import.meta.url));
const appSource = readFileSync(resolve(here, "../App.jsx"), "utf8");

describe("GLOSSARY entries", () => {
  const entries = Object.entries(GLOSSARY);

  it("has entries", () => {
    expect(entries.length).toBeGreaterThan(10);
  });

  it.each(entries)("%s has a label and a plain-language explanation", (key, entry) => {
    expect(typeof entry.label).toBe("string");
    expect(entry.label.trim().length).toBeGreaterThan(0);
    expect(typeof entry.short).toBe("string");
    expect(entry.short.trim().length).toBeGreaterThan(10);
  });

  it.each(entries)("%s: the optional 'where' hint is a non-empty string when present", (key, entry) => {
    if (entry.where !== undefined) {
      expect(typeof entry.where).toBe("string");
      expect(entry.where.trim().length).toBeGreaterThan(0);
    }
  });

  it("defines the core vulnerability terms the table headers rely on", () => {
    for (const key of ["cve", "cvss", "severity", "asset", "priority"]) {
      expect(GLOSSARY[key], `missing glossary entry: ${key}`).toBeDefined();
    }
  });

  it("defines the terms behind the Validation statuses and the AI-confidence label", () => {
    for (const key of ["needsReview", "noFlags", "aiConfidence", "falsePositive"]) {
      expect(GLOSSARY[key], `missing glossary entry: ${key}`).toBeDefined();
    }
  });
});

describe("glossary keys used in App.jsx", () => {
  it("every <Term k=\"…\"> refers to a real entry", () => {
    const used = [...appSource.matchAll(/<Term\s+k=["']([^"']+)["']/g)].map(m => m[1]);
    expect(used.length).toBeGreaterThan(0);
    const missing = [...new Set(used)].filter(k => !(k in GLOSSARY));
    expect(missing).toEqual([]);
  });

  it("every key chosen inside a dynamic <Term k={…}> expression is a real entry", () => {
    // e.g. <Term k={row.status === "No flags" ? "noFlags" : "needsReview"}> — the plain
    // <Term k="…"> check above can't see these. Only literals after `?` / `:` are keys.
    const exprs = [...appSource.matchAll(/<Term\s+k=\{([^}]*)\}/g)].map(m => m[1]);
    const keys = exprs.flatMap(e => [...e.matchAll(/[?:]\s*["']([^"']+)["']/g)].map(m => m[1]));
    expect(keys.filter(k => !(k in GLOSSARY))).toEqual([]);
  });

  it("every column header in HEADER_TERMS maps to a real entry", () => {
    const block = appSource.match(/const HEADER_TERMS = \{([^}]*)\}/);
    expect(block).not.toBeNull();
    const keys = [...block[1].matchAll(/:\s*["']([^"']+)["']/g)].map(m => m[1]);
    expect(keys.length).toBeGreaterThan(0);
    expect(keys.filter(k => !(k in GLOSSARY))).toEqual([]);
  });
});

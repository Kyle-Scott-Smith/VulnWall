// Tests for loadProfilePrefs / saveProfilePrefs / _fmtDate in App.jsx — the
// per-account preferences kept in the browser's localStorage. The stored
// value is user-controllable (and can be corrupted or blocked), so loading
// must never throw and must never hand back a wrongly-typed field.
// (Needs the exports added by scripts/export-test-helpers.sh — see appHelpers.test.js.)
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadProfilePrefs, saveProfilePrefs, _fmtDate } from "../App.jsx";

const DEFAULTS = { notifications: false, defaultAssign: "Security Team" };

function fakeStorage(initial = {}) {
  const data = { ...initial };
  return {
    data,
    getItem: k => (k in data ? data[k] : null),
    setItem: (k, v) => { data[k] = String(v); },
    removeItem: k => { delete data[k]; },
  };
}

let storage;
beforeEach(() => {
  storage = fakeStorage();
  vi.stubGlobal("localStorage", storage);
});
afterEach(() => vi.unstubAllGlobals());

describe("loadProfilePrefs", () => {
  it("returns the defaults when no email is given", () => {
    expect(loadProfilePrefs("")).toEqual(DEFAULTS);
    expect(loadProfilePrefs(null)).toEqual(DEFAULTS);
    expect(loadProfilePrefs(undefined)).toEqual(DEFAULTS);
  });

  it("returns the defaults when nothing has been saved for that account", () => {
    expect(loadProfilePrefs("a@b.co")).toEqual(DEFAULTS);
  });

  it("returns what was saved", () => {
    saveProfilePrefs("a@b.co", { notifications: true, defaultAssign: "IT Operations" });
    expect(loadProfilePrefs("a@b.co")).toEqual({ notifications: true, defaultAssign: "IT Operations" });
  });

  it("keeps each account's preferences separate", () => {
    saveProfilePrefs("a@b.co", { notifications: true, defaultAssign: "A-team" });
    saveProfilePrefs("c@d.co", { notifications: false, defaultAssign: "C-team" });
    expect(loadProfilePrefs("a@b.co").defaultAssign).toBe("A-team");
    expect(loadProfilePrefs("c@d.co").defaultAssign).toBe("C-team");
    expect(loadProfilePrefs("nobody@x.co")).toEqual(DEFAULTS);
  });

  it("falls back to the defaults for corrupt JSON instead of throwing", () => {
    saveProfilePrefs("a@b.co", DEFAULTS);
    const key = Object.keys(storage.data)[0];
    storage.data[key] = "{not valid json";
    expect(loadProfilePrefs("a@b.co")).toEqual(DEFAULTS);
  });

  it("replaces wrongly-typed fields individually, keeping the valid ones", () => {
    saveProfilePrefs("a@b.co", DEFAULTS);
    const key = Object.keys(storage.data)[0];
    storage.data[key] = JSON.stringify({ notifications: "yes", defaultAssign: "Ops" });
    expect(loadProfilePrefs("a@b.co")).toEqual({ notifications: false, defaultAssign: "Ops" });
    storage.data[key] = JSON.stringify({ notifications: true, defaultAssign: 42 });
    expect(loadProfilePrefs("a@b.co")).toEqual({ notifications: true, defaultAssign: "Security Team" });
  });

  it("ignores unknown extra fields", () => {
    saveProfilePrefs("a@b.co", DEFAULTS);
    const key = Object.keys(storage.data)[0];
    storage.data[key] = JSON.stringify({ notifications: true, defaultAssign: "Ops", extra: "x" });
    expect(loadProfilePrefs("a@b.co")).toEqual({ notifications: true, defaultAssign: "Ops" });
  });

  it("returns the defaults when storage is unavailable", () => {
    vi.stubGlobal("localStorage", { getItem() { throw new Error("blocked"); } });
    expect(loadProfilePrefs("a@b.co")).toEqual(DEFAULTS);
  });
});

describe("saveProfilePrefs", () => {
  it("does nothing without an email", () => {
    saveProfilePrefs("", { notifications: true, defaultAssign: "x" });
    saveProfilePrefs(null, { notifications: true, defaultAssign: "x" });
    expect(Object.keys(storage.data)).toEqual([]);
  });

  it("stores under a key namespaced by email", () => {
    saveProfilePrefs("a@b.co", DEFAULTS);
    const keys = Object.keys(storage.data);
    expect(keys).toHaveLength(1);
    expect(keys[0]).toContain("a@b.co");
  });

  it("overwrites the previous value", () => {
    saveProfilePrefs("a@b.co", { notifications: false, defaultAssign: "One" });
    saveProfilePrefs("a@b.co", { notifications: true, defaultAssign: "Two" });
    expect(Object.keys(storage.data)).toHaveLength(1);
    expect(loadProfilePrefs("a@b.co").defaultAssign).toBe("Two");
  });

  it("fails silently when storage is blocked (e.g. private browsing)", () => {
    vi.stubGlobal("localStorage", { setItem() { throw new Error("QuotaExceeded"); } });
    expect(() => saveProfilePrefs("a@b.co", DEFAULTS)).not.toThrow();
  });
});

describe("_fmtDate", () => {
  it("shows an em dash for a missing date", () => {
    expect(_fmtDate(null)).toBe("—");
    expect(_fmtDate(undefined)).toBe("—");
    expect(_fmtDate("")).toBe("—");
  });

  it("formats an ISO timestamp with month, day and year", () => {
    const out = _fmtDate("2026-08-09T12:00:00+00:00");
    expect(out).toMatch(/2026/);
    expect(out).toMatch(/9/);
    expect(out).not.toBe("—");
  });

  // Documents today's behaviour: `new Date("garbage")` doesn't throw, it
  // produces an Invalid Date whose formatted text is "Invalid Date", so the
  // function's catch block (which would show the first 10 characters) never
  // runs for bad strings. Harmless in practice — the backend only sends ISO
  // timestamps — but worth knowing if the fallback ever matters.
  it("shows 'Invalid Date' for an unparseable string rather than falling back to the raw text", () => {
    expect(_fmtDate("garbage")).toMatch(/invalid/i);
  });
});

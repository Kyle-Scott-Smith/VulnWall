// Tests for the small pure helpers in App.jsx that every screen leans on:
// role-based navigation, the client-side password rules, option/checkbox
// helpers for the questionnaire, search and sort used by the wizard tables.
//
// SETUP: these helpers weren't exported originally. Run
//     sh scripts/export-test-helpers.sh
// once (it only prepends `export ` to nine function declarations — no
// behaviour change). Until then the first test below fails with a message
// saying exactly that, instead of every test failing with "not a function".
import { describe, expect, it } from "vitest";
import * as App from "../App.jsx";

const { navTabsForRole, passwordError, optionLabel, toggleMulti, matchesSearch, sortRows } = App;

describe("test setup", () => {
  it("App.jsx exports the helpers under test (run scripts/export-test-helpers.sh if this fails)", () => {
    for (const name of ["navTabsForRole", "passwordError", "optionLabel", "toggleMulti", "matchesSearch", "sortRows",
      "loadProfilePrefs", "saveProfilePrefs", "_fmtDate"]) {
      expect(typeof App[name], `${name} is not exported from App.jsx`).toBe("function");
    }
  });
});

describe("navTabsForRole", () => {
  it("gives analysts the four working tabs", () => {
    expect(navTabsForRole("analyst")).toEqual(["dashboard", "upload-scan", "history", "tickets"]);
  });

  it("hides Upload Scan from viewers (they can't run scans)", () => {
    expect(navTabsForRole("viewer")).toEqual(["dashboard", "history", "tickets"]);
  });

  it("adds the Users tab, last, for admins only", () => {
    expect(navTabsForRole("admin")).toEqual(["dashboard", "upload-scan", "history", "tickets", "users"]);
    expect(navTabsForRole("analyst")).not.toContain("users");
    expect(navTabsForRole("viewer")).not.toContain("users");
  });

  it("falls back to the analyst tabs for an unknown or missing role", () => {
    expect(navTabsForRole(undefined)).toEqual(navTabsForRole("analyst"));
    expect(navTabsForRole("superuser")).toEqual(navTabsForRole("analyst"));
  });

  it("returns a fresh array each call so callers can't corrupt it for the next render", () => {
    const first = navTabsForRole("analyst");
    first.push("hacked");
    expect(navTabsForRole("analyst")).not.toContain("hacked");
  });
});

describe("passwordError", () => {
  it("accepts a password meeting every rule", () => {
    expect(passwordError("Str0ng!pass")).toBeNull();
  });

  // Same table as the backend's test_auth.py — the two sides must agree, or
  // the form would accept passwords the server then rejects (or vice versa).
  it.each([
    ["Sh1!", /at least 8/],
    ["alllower1!", /uppercase/],
    ["ALLUPPER1!", /lowercase/],
    ["NoNumber!!", /number/],
    ["NoSymbol11", /symbol/],
  ])("rejects %s", (password, message) => {
    expect(passwordError(password)).toMatch(message);
  });

  it("reports the first failing rule when several fail", () => {
    expect(passwordError("")).toMatch(/at least 8/);
    expect(passwordError("abcdefgh")).toMatch(/uppercase/);
  });

  it("counts a space or underscore as a symbol", () => {
    expect(passwordError("Passw0rd word")).toBeNull();
    expect(passwordError("Passw0rd_")).toBeNull();
  });

  it("accepts exactly 8 characters", () => {
    expect(passwordError("Abcdef1!")).toBeNull();
    expect(passwordError("Abcde1!")).toMatch(/at least 8/);
  });
});

describe("optionLabel", () => {
  const options = [{ value: "a", label: "Alpha" }, { value: "b", label: "Beta" }];
  it("looks up the label for a value", () => {
    expect(optionLabel(options, "b")).toBe("Beta");
  });
  it("falls back to the raw value when it isn't a known option", () => {
    expect(optionLabel(options, "zzz")).toBe("zzz");
  });
  it("copes with an empty options list", () => {
    expect(optionLabel([], "x")).toBe("x");
  });
});

describe("toggleMulti", () => {
  it("adds a value that isn't selected and removes one that is", () => {
    expect(toggleMulti(["pii"], "financial")).toEqual(["pii", "financial"]);
    expect(toggleMulti(["pii", "financial"], "pii")).toEqual(["financial"]);
  });

  it("selecting 'none' clears everything else", () => {
    expect(toggleMulti(["pii", "financial"], "none")).toEqual(["none"]);
  });

  it("selecting 'none' again deselects it", () => {
    expect(toggleMulti(["none"], "none")).toEqual([]);
  });

  it("selecting anything else drops 'none'", () => {
    expect(toggleMulti(["none"], "pii")).toEqual(["pii"]);
  });

  it("supports a custom exclusive value", () => {
    expect(toggleMulti(["a", "b"], "all", "all")).toEqual(["all"]);
    expect(toggleMulti(["all"], "a", "all")).toEqual(["a"]);
  });

  it("does not mutate the list it was given", () => {
    const list = ["pii"];
    toggleMulti(list, "financial");
    toggleMulti(list, "pii");
    expect(list).toEqual(["pii"]);
  });
});

describe("matchesSearch", () => {
  const row = { id: "CVE-2024-3094", title: "XZ backdoor", desc: "Malicious code in liblzma", asset: "web-01" };

  it("matches everything for an empty or blank term", () => {
    expect(matchesSearch(row, "")).toBe(true);
    expect(matchesSearch(row, "   ")).toBe(true);
  });

  it("searches id, title, description and asset, case-insensitively", () => {
    expect(matchesSearch(row, "cve-2024")).toBe(true);
    expect(matchesSearch(row, "BACKDOOR")).toBe(true);
    expect(matchesSearch(row, "liblzma")).toBe(true);
    expect(matchesSearch(row, "WEB-01")).toBe(true);
  });

  it("trims the term", () => {
    expect(matchesSearch(row, "  xz  ")).toBe(true);
  });

  it("returns false when nothing matches", () => {
    expect(matchesSearch(row, "nginx")).toBe(false);
  });

  it("ignores fields that are missing and doesn't search other fields like severity", () => {
    expect(matchesSearch({ id: "A" }, "b")).toBe(false);
    expect(matchesSearch({ id: "A", severity: "Critical" }, "critical")).toBe(false);
  });

  it("handles non-string field values", () => {
    expect(matchesSearch({ id: 12345 }, "234")).toBe(true);
  });
});

describe("sortRows", () => {
  const rows = [
    { id: "c", severity: "Low", cvss: 2.1, priority: "P3", title: "banana" },
    { id: "a", severity: "Critical", cvss: 9.8, priority: "P1 - Critical", title: "Apple" },
    { id: "b", severity: "High", cvss: 7.5, priority: "P2", title: "cherry" },
  ];
  const ids = list => list.map(r => r.id);

  it("returns the rows untouched when there is no sort field or it is 'None'", () => {
    expect(sortRows(rows, null)).toBe(rows);
    expect(sortRows(rows, "None")).toBe(rows);
    expect(sortRows(rows, undefined)).toBe(rows);
  });

  it("ranks severity by seriousness, not alphabetically", () => {
    expect(ids(sortRows(rows, "severity", "asc"))).toEqual(["c", "b", "a"]);
    expect(ids(sortRows(rows, "severity", "desc"))).toEqual(["a", "b", "c"]);
  });

  it("treats an unknown severity as lowest", () => {
    const withUnknown = [{ id: "x", severity: "Unknown" }, { id: "y", severity: "Low" }];
    expect(ids(sortRows(withUnknown, "severity", "asc"))).toEqual(["x", "y"]);
  });

  it("ranks priority across both label styles (P1 and 'P1 - Critical')", () => {
    expect(ids(sortRows(rows, "priority", "desc"))).toEqual(["a", "b", "c"]);
  });

  it("sorts numbers numerically", () => {
    expect(ids(sortRows(rows, "cvss", "asc"))).toEqual(["c", "b", "a"]);
    const tens = [{ id: "ten", cvss: 10 }, { id: "nine", cvss: 9 }];
    expect(ids(sortRows(tens, "cvss", "asc"))).toEqual(["nine", "ten"]);  // not "10" < "9"
  });

  it("sorts text case-insensitively", () => {
    expect(ids(sortRows(rows, "title", "asc"))).toEqual(["a", "c", "b"]);  // Apple, banana, cherry
  });

  it("defaults to ascending", () => {
    expect(ids(sortRows(rows, "cvss"))).toEqual(["c", "b", "a"]);
  });

  it("treats missing values as 0 so they sort first ascending", () => {
    const mixed = [{ id: "has", cvss: 5 }, { id: "none" }];
    expect(ids(sortRows(mixed, "cvss", "asc"))).toEqual(["none", "has"]);
  });

  it("does not mutate the input array", () => {
    const copy = [...rows];
    sortRows(rows, "cvss", "desc");
    expect(rows).toEqual(copy);
  });
});

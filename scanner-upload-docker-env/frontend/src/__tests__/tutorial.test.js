// Tests for the tutorial's "seen it already" flag in Tutorial.jsx. It lives
// in localStorage, which can be blocked; the contract is that a blocked store
// must never trap the user in a tutorial they can't dismiss.
import { afterEach, describe, expect, it, vi } from "vitest";
import { hasCompletedTutorial, resetTutorial } from "../Tutorial";

afterEach(() => vi.unstubAllGlobals());

function stubStorage(overrides = {}) {
  const calls = { get: [], remove: [] };
  vi.stubGlobal("localStorage", {
    getItem: k => { calls.get.push(k); return null; },
    removeItem: k => { calls.remove.push(k); },
    setItem: () => {},
    ...overrides,
  });
  return calls;
}

describe("hasCompletedTutorial", () => {
  it("is false for a first-time visitor", () => {
    stubStorage();
    expect(hasCompletedTutorial()).toBe(false);
  });

  it("is true once the flag has been stored as 'true'", () => {
    stubStorage({ getItem: () => "true" });
    expect(hasCompletedTutorial()).toBe(true);
  });

  it("only treats the exact string 'true' as completed", () => {
    for (const value of ["false", "1", "yes", "", "TRUE"]) {
      stubStorage({ getItem: () => value });
      expect(hasCompletedTutorial()).toBe(false);
    }
  });

  it("fails safe — counts as completed — when storage is blocked", () => {
    stubStorage({ getItem: () => { throw new Error("SecurityError"); } });
    expect(hasCompletedTutorial()).toBe(true);
  });
});

describe("resetTutorial", () => {
  it("removes the same key that hasCompletedTutorial reads", () => {
    const calls = stubStorage();
    hasCompletedTutorial();
    resetTutorial();
    expect(calls.remove).toHaveLength(1);
    expect(calls.remove[0]).toBe(calls.get[0]);
  });

  it("makes the tutorial show again", () => {
    const store = {};
    let usedKey;
    vi.stubGlobal("localStorage", {
      getItem: k => { usedKey = k; return store[k] ?? null; },
      setItem: (k, v) => { store[k] = v; },
      removeItem: k => { delete store[k]; },
    });
    hasCompletedTutorial();          // learn which key the module uses
    store[usedKey] = "true";         // ...and mark the tutorial as done
    expect(hasCompletedTutorial()).toBe(true);
    resetTutorial();
    expect(hasCompletedTutorial()).toBe(false);
  });

  it("doesn't throw when storage is blocked", () => {
    stubStorage({ removeItem: () => { throw new Error("blocked"); } });
    expect(() => resetTutorial()).not.toThrow();
  });
});

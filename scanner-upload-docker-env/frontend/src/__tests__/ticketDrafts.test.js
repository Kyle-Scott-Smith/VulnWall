import { describe, it, expect } from "vitest";
import { priorityCode, defaultPriority, defaultAssignee, defaultTicketDraft, draftToSavedTicket, restoreDrafts } from "../ticketDrafts";

describe("priorityCode", () => {

  it("shortens the dropdown labels", () => {
    expect(priorityCode("P1 - Critical")).toBe("P1");
    expect(priorityCode("P2 - High")).toBe("P2");
    expect(priorityCode("P3 - Medium")).toBe("P3");
  });

  it("falls back to P3 for anything unrecognised", () => {
    expect(priorityCode("")).toBe("P3");
    expect(priorityCode(undefined)).toBe("P3");
  });
});

describe("defaultTicketDraft", () => {

  it("derives priority and assignee from severity", () => {
    const d = defaultTicketDraft("CVE-1", { severity: "Critical", asset: "web-1" }, { title: "Bad bug", why: "Because" });
    expect(d).toMatchObject({ id: "CVE-1", priority: "P1 - Critical", assignTo: "Security Team", asset: "web-1", description: "Because" });
    expect(d.title).toBe("[Critical] CVE-1 — Bad bug");
    expect(defaultTicketDraft("CVE-2", { severity: "Medium" }, {})).toMatchObject({ priority: "P3 - Medium", assignTo: "IT Operations" });
  });
});

describe("default assignee (Profile → Default assign to)", () => {

  it("uses the user's preference for every severity", () => {
    for (const severity of ["Critical", "High", "Medium", "Low"]) {
      expect(defaultTicketDraft("CVE-1", { severity }, {}, { assignee: "Infrastructure" }).assignTo).toBe("Infrastructure");
    }
  });

  it("only falls back to the severity-based default when no preference is set", () => {
    expect(defaultTicketDraft("CVE-1", { severity: "Critical" }, {}, {}).assignTo).toBe("Security Team");
    expect(defaultTicketDraft("CVE-1", { severity: "Low" }, {}, { assignee: "" }).assignTo).toBe("IT Operations");
  });
});

describe("draftToSavedTicket (edits are carried forward)", () => {
  const edited = {
    id: "CVE-1", severity: "Critical", asset: "web-1",
    title: "My edited title", description: "My edited description",
    priority: "P3 - Medium", assignTo: "Infrastructure",
  };
  const detail = { cvss: 9.8, confidence: 80, fixes: ["Patch it"], why: "ORIGINAL AI TEXT" };

  it("saves the user's edits, not values rebuilt from the finding", () => {
    const t = draftToSavedTicket(edited, detail, { date: "01-01-2026" });
    expect(t.title).toBe("My edited title");
    expect(t.why).toBe("My edited description");
    expect(t.priority).toBe("P3");           // not re-derived as P1 from severity "Critical"
    expect(t.assigned).toBe("Infrastructure"); // not re-derived as "Security Team"
    expect(t.cve).toBe("CVE-1");
  });

  it("saves a missing confidence as null, not 0 or an invented number", () => {
    expect(draftToSavedTicket(edited, { cvss: 5 }, {}).confidence).toBeNull();
    expect(draftToSavedTicket(edited, { confidence: 0 }, {}).confidence).toBe(0);
  });

  it("never sends an id, so the server numbers the ticket", () => {
    expect("id" in draftToSavedTicket(edited, detail, {})).toBe(false);
  });

  it("links the Jira issue when one was created", () => {
    const t = draftToSavedTicket(edited, detail, { jira: { issueKey: "VULN-7", url: "https://x/VULN-7" } });
    expect(t.jiraIssueKey).toBe("VULN-7");
    expect(t.jiraUrl).toBe("https://x/VULN-7");
    expect(draftToSavedTicket(edited, detail, {}).jiraIssueKey).toBeNull();
  });
});

describe("restoreDrafts", () => {
  const build = id => ({ id, title: `default ${id}` });

  it("restores edits and decisions when the selection is unchanged", () => {
    const saved = { forms: [{ id: "A", title: "edited" }, { id: "B", title: "b" }], submitted: ["approved", null] };
    const r = restoreDrafts(saved, ["A", "B"], build);
    expect(r.forms[0].title).toBe("edited");
    expect(r.submitted).toEqual(["approved", null]);
  });

  it("starts fresh when the selection changed", () => {
    const saved = { forms: [{ id: "A", title: "edited" }], submitted: ["approved"] };
    const r = restoreDrafts(saved, ["A", "C"], build);
    expect(r.forms.map(f => f.title)).toEqual(["default A", "default C"]);
    expect(r.submitted).toEqual([null, null]);
  });

  it("starts fresh when nothing was saved", () => {
    expect(restoreDrafts(null, ["A"], build).submitted).toEqual([null]);
  });
});

// ---------------------------------------------------------------------------
// Added coverage
// ---------------------------------------------------------------------------
describe("priorityCode — more inputs", () => {
  it("keeps a code that is already short, and falls back for null", () => {
    expect(priorityCode("P2")).toBe("P2");
    expect(priorityCode(null)).toBe("P3");
    expect(priorityCode("Critical")).toBe("P3");
  });
});

describe("defaultPriority", () => {
  it("maps severity to the dropdown labels, with everything else Medium", () => {
    expect(defaultPriority("Critical")).toBe("P1 - Critical");
    expect(defaultPriority("High")).toBe("P2 - High");
    for (const s of ["Medium", "Low", "Unknown", "", undefined]) expect(defaultPriority(s)).toBe("P3 - Medium");
  });

  it("only ever produces labels that priorityCode reads back to the same P-number", () => {
    expect(["Critical", "High", "Medium"].map(s => priorityCode(defaultPriority(s)))).toEqual(["P1", "P2", "P3"]);
  });
});

describe("defaultAssignee", () => {
  it("prefers the user's setting over the severity default", () => {
    expect(defaultAssignee("Critical", "Infra")).toBe("Infra");
    expect(defaultAssignee("Low", "Infra")).toBe("Infra");
  });

  it("falls back to severity when the preference is missing or empty", () => {
    expect(defaultAssignee("Critical")).toBe("Security Team");
    expect(defaultAssignee("High", "")).toBe("IT Operations");
    expect(defaultAssignee(undefined, null)).toBe("IT Operations");
  });
});

describe("defaultTicketDraft — missing data", () => {
  it("leaves asset and description empty rather than inventing them", () => {
    const d = defaultTicketDraft("CVE-9", { severity: "High" }, {});
    expect(d).toMatchObject({ id: "CVE-9", severity: "High", priority: "P2 - High", asset: "", description: "" });
  });

  it("works with no row or detail at all", () => {
    expect(() => defaultTicketDraft("CVE-9")).not.toThrow();
    expect(defaultTicketDraft("CVE-9").assignTo).toBe("IT Operations");
  });
});

describe("draftToSavedTicket — defaults and pass-through", () => {
  const draft = { id: "CVE-1", title: "T", description: "D", priority: "P2 - High", assignTo: "Ops" };

  it("always saves status Open and the date it was given", () => {
    const t = draftToSavedTicket(draft, {}, { date: "14-10-2026" });
    expect(t).toMatchObject({ status: "Open", date: "14-10-2026" });
  });

  it("defaults cvss to 0 and fixes to [] when the finding has none", () => {
    expect(draftToSavedTicket(draft, {}, {})).toMatchObject({ cvss: 0, fixes: [] });
  });

  it("copies cvss and fixes from the finding", () => {
    expect(draftToSavedTicket(draft, { cvss: 7.5, fixes: ["a", "b"] }, {})).toMatchObject({ cvss: 7.5, fixes: ["a", "b"] });
  });

  it("treats a non-numeric confidence as not assessed", () => {
    expect(draftToSavedTicket(draft, { confidence: "80" }, {}).confidence).toBeNull();
  });

  it("round-trips an untouched default draft to the same priority and assignee", () => {
    const fresh = defaultTicketDraft("CVE-1", { severity: "High" }, { title: "x", why: "y" });
    const t = draftToSavedTicket(fresh, {}, {});
    expect(t).toMatchObject({ priority: "P2", assigned: "IT Operations", why: "y" });
  });

  it("saves null Jira fields when no Jira issue was created", () => {
    expect(draftToSavedTicket(draft, {}, {})).toMatchObject({ jiraIssueKey: null, jiraUrl: null });
  });
});

describe("restoreDrafts — more cases", () => {
  const build = id => ({ id, title: `default ${id}` });

  it("starts fresh when the same ids come back in a different order", () => {
    const saved = { forms: [{ id: "A", title: "edited" }, { id: "B", title: "b" }], submitted: ["approved", "rejected"] };
    const r = restoreDrafts(saved, ["B", "A"], build);
    expect(r.forms.map(f => f.title)).toEqual(["default B", "default A"]);
    expect(r.submitted).toEqual([null, null]);
  });

  it("starts fresh when the selection grew or shrank", () => {
    const saved = { forms: [{ id: "A", title: "edited" }, { id: "B", title: "b" }], submitted: ["approved", null] };
    expect(restoreDrafts(saved, ["A"], build).forms.map(f => f.title)).toEqual(["default A"]);
  });

  it("copes with no selection at all", () => {
    expect(restoreDrafts(null, undefined, build)).toEqual({ forms: [], submitted: [] });
  });
});

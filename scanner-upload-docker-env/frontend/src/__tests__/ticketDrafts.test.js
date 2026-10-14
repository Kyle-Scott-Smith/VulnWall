import { describe, it, expect } from "vitest";
import { priorityCode, defaultTicketDraft, draftToSavedTicket, restoreDrafts } from "../ticketDrafts";

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

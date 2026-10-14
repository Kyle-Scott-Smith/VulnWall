// Shared shape for a ticket as it moves through the wizard.
//
// Why this exists: the Generate Ticket step lets the user edit each ticket's
// title, description, priority and assignee, but the Review & Send step used
// to rebuild every ticket from the underlying finding and throw those edits
// away. Both steps now use the helpers below, and the *draft object itself*
// (edits included) is what gets passed from one step to the next and sent to
// Jira / saved.

// "P1 - Critical" -> "P1". Tickets are stored and shown with the short code.
export function priorityCode(priority) {
  const m = /^P\d/.exec(priority || "");
  return m ? m[0] : "P3";
}

export function defaultPriority(severity) {
  return severity === "Critical" ? "P1 - Critical" : severity === "High" ? "P2 - High" : "P3 - Medium";
}

// `preferred` is the user's "Default assign to" setting (Profile). When it's
// set, every new draft starts with it; the severity-based fallback only
// applies if there is no preference.
export function defaultAssignee(severity, preferred) {
  if (preferred) return preferred;
  return severity === "Critical" ? "Security Team" : "IT Operations";
}

// The draft the Generate Ticket step starts from, before the user edits it.
// `id` is the finding id (a CVE id, or the title for findings without one) —
// it is NOT the saved ticket's id; the backend assigns that.
export function defaultTicketDraft(id, row = {}, detail = {}, { assignee } = {}) {
  const severity = row.severity || "";
  return {
    id,
    title: `[${severity}] ${id} — ${detail.title || ""}`,
    description: detail.why || "",
    severity,
    priority: defaultPriority(severity),
    asset: row.asset || "",
    assignTo: defaultAssignee(severity, assignee),
  };
}

// Turns an approved draft into the body the backend stores. No `id` is sent
// on purpose: the server numbers new tickets, so a second batch can never
// overwrite the first.
export function draftToSavedTicket(draft, detail = {}, { date, jira } = {}) {
  return {
    cve: draft.id,
    title: draft.title,
    priority: priorityCode(draft.priority),
    status: "Open",
    assigned: draft.assignTo,
    date,
    cvss: detail.cvss || 0,
    // null (not 0) when the AI gave no confidence, so it displays as "Not assessed".
    confidence: typeof detail.confidence === "number" ? detail.confidence : null,
    fixes: detail.fixes || [],
    // The ticket's description is stored in `why`, so an edited description
    // is what is saved and shown in the Tickets page.
    why: draft.description,
    jiraIssueKey: jira?.issueKey || null,
    jiraUrl: jira?.url || null,
  };
}

// Reuses saved Generate Ticket work (edits + approve/reject decisions) when
// the user comes back to the step, but only if it still matches the current
// selection — otherwise the saved drafts belong to a different selection.
export function restoreDrafts(saved, selected, buildDefault) {
  const ids = selected || [];
  const sameSelection =
    saved && saved.forms.length === ids.length && saved.forms.every((f, i) => f.id === ids[i]);
  if (sameSelection) return { forms: saved.forms, submitted: saved.submitted };
  const forms = ids.map(buildDefault);
  return { forms, submitted: forms.map(() => null) };
}

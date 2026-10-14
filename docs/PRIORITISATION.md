# Prioritisation and AI Analysis

Every finding passes through `POST /api/analyze` (`ai_analysis.py`), which does
two independent things:

1. computes a **deterministic business priority score** (plain code), and
2. asks the **local Ollama model** for a written analysis.

Because the score never depends on the model, ordering stays meaningful even
when Ollama is down.

---

## 1. Business priority score

Function: `compute_business_priority_score(vuln, business_context)`.

### Inputs

The finding's `cvss` and `severity`, plus the user's saved questionnaire
(`business_context.py`). If the user hasn't completed the questionnaire (or isn't
signed in), `business_context` is `None`.

### Step by step

1. **Base score** — the finding's CVSS if it is a number; otherwise by severity:

   | Severity | Base |
   |---|---|
   | Critical | 10.0 |
   | High | 7.5 |
   | Medium | 5.0 |
   | Low | 2.5 |
   | Unknown / other | 1.0 |

2. **No questionnaire?** The score is just the base, rounded to 2 decimals
   (i.e. ordering degrades gracefully to CVSS-only).
3. **Criticality tier multiplier** (from "how bad would an outage be?"):

   | Tier | Answer | Multiplier |
   |---|---|---|
   | 1 | Life-safety impact | 1.5 |
   | 2 | Major business disruption | 1.25 |
   | 3 | Moderate disruption | 1.0 |
   | 4 | Minor inconvenience | 0.85 |
   | 5 | No significant impact | 0.7 |

   `score = base × multiplier` (an unrecognised tier counts as 1.0).
4. **Top-concern tier boost** — if the top concern is `physical_safety` or
   `operational_downtime`: `score += base × (multiplier − 1) × 0.5`.
5. **Exposure bonus** — a number added up from the pieces below:

   | Factor | Bonus |
   |---|---|
   | Internet-facing: `public` / `mixed` / `internal` | +1.5 / +0.75 / 0 |
   | If `public` or `mixed`: the **highest** weight among the exposed systems — `admin_panel` 1.0, `remote_access` 1.0, `api` 0.75, `other` 0.5, `website` 0.4 | + that weight |
   | Any sensitive data type (`credentials`, `financial`, `medical`, `pii`, `intellectual_property`) — flat, not per type | +1.0 (×2 if top concern is `customer_trust`) |
   | Any compliance framework other than `none` — flat, not per framework | +0.75 (×2 if top concern is `legal_regulatory`) |
   | System directly generates revenue | +0.5 (×2 if top concern is `revenue_loss`) |
   | Previous breach answered `yes` | +0.5 |

   The "top concern" doubling applies to whichever bonus matches what the
   organisation said would worry them most; it doesn't add a separate bonus.
6. **Air-gap discount** — if the organisation has air-gapped systems, the whole
   exposure bonus is multiplied by 0.5 (the tier multiplier is untouched).
7. **Final:** `score × (1 + exposure bonus)`, rounded to 2 decimals.

### Worked examples

*CVSS 9.0, tier 1, public, personal data, HIPAA, not air-gapped, no top-concern effects*
`9.0 × 1.5 × (1 + 1.5 + 1.0 + 0.75) = 57.375` → shown as ≈ 57.38 (this case is in the test suite).

*CVSS 8.0, tier 2, internal, GDPR, top concern `operational_downtime`*
`8.0 × 1.25 = 10.0`; boost `8.0 × 0.25 × 0.5 = 1.0` → 11.0; exposure bonus 0.75 (GDPR) → `11.0 × 1.75 = 19.25`.

### Where the score is used

- `/api/analyze` sorts findings by it (highest first).
- The UI's "Business Priority" sort, the Excel export column, and the per-finding tooltip show it.
- It is **not** used for ticket priority: a draft ticket starts as P1 (Critical), P2 (High) or P3 (everything else) from the finding's severity, and can be edited in the Generate Ticket step.

### Criticality label caveat

The finding detail page shows a "High / Medium / Low criticality" label from
`criticalityBand(score, cvss)`. The business multiplier cancels out in that
formula, so the label always equals the plain CVSS band (≥ 7.0 High, ≥ 4.0
Medium, otherwise Low). Business context only changes the numeric score and the
ordering. A regression test (`criticalityBand.test.js`) documents this.

---

## 2. AI analysis

### What the model returns

Strict JSON with exactly these fields (anything else fails validation):

| Field | Meaning |
|---|---|
| `why` | 2–4 sentences, < 600 chars: the technical mechanism — what's broken, how it's exploited, what an attacker gains |
| `business_impact` | 2–4 sentences, < 600 chars: consequences for *this* organisation. Must cite at least two questionnaire details by name. Empty string if there is no questionnaire. |
| `fixes` | 2–4 short, concrete remediation steps. The prompt forbids inventing patched version numbers; it asks for wording like "upgrade to the vendor's current patched release". |
| `confidence` | integer 0–100; lowered when the description or CVSS is thin |
| `priority_tier` | `P1`–`P4`. Anchored to CVSS (no P1/P2 below 7.0 without a known public exploit, no P3/P4 at 9.0+), adjusted by at most one tier for business context. Returned but **not displayed** in the UI. |

The prompt is grounded in the scan data only (CVE id, title, description up to
3,000 characters, CVSS, severity, package and installed version) plus a
"Business context" block built from the questionnaire. Ollama is called in JSON
mode, which guarantees parseable JSON but not the schema — the code checks the
fields and types itself.

### Retry and fallback

1. Full prompt, up to `AI_MAX_RETRIES + 1` attempts (default 3).
2. A simplified prompt, one attempt.
3. **Template fallback** — no AI text:
   - `ai_generated: false`, `confidence: 30`
   - `why` = the scanner's description
   - `business_impact` = a short canned sentence naming the questionnaire details (or empty)
   - `fixes` = a generic upgrade/review step plus "Manual review required"
   - `priority_tier` from severity (Critical → P1 … Low → P4)

`business_priority_score` is attached in every case.

### Cache

Successful analyses are cached **in memory** for the life of the backend
process, keyed by CVE id (or title) plus a signature of the questionnaire answers
that affect the output, so one organisation's tailored text is never reused for
another. Cached results come back with `from_cache: true`. Template fallbacks are
not cached, and the cache is lost on restart.

### How the UI uses the result

- **Validation step:** a finding shows **No flags** unless `ai_generated` is
  false (a template fallback) or confidence is below 60; those are **Needs
  Review**. A finding with no confidence value isn't flagged for confidence. If
  no AI result exists at all, a finding has no flags only when it has both a
  CVSS score and a description. These are checks on the data, not a
  verification against external sources.
- **Detail page:** *Why This Matters*, *Business Impact* (hidden if empty),
  *Suggested Fix*; confidence is highlighted below 60% and shown as *Not assessed* when the AI gave none.
- If `/api/analyze` fails entirely, the wizard continues with placeholder
  explanations built from the raw scan data.

### Tuning

If many findings show `ai_generated: false`, the model is usually failing the
JSON/field check rather than anything being broken. Try a larger model
(`OLLAMA_MODEL`, see `README-ollama-swap.md`) or raise `AI_MAX_RETRIES`. Analysis
time grows with the number of unique findings (`AI_ANALYSIS_CONCURRENCY` controls
parallelism, but Ollama itself may serialise requests on a CPU-only machine).

# Business context in AI analysis + chatbot

The post-signup questionnaire (`business_context.py`, `BusinessContextStep`
in the frontend) collects sector, data sensitivity, business criticality,
internet exposure, compliance scope, air-gapping, and security-team status
for the signed-in user's organisation. Previously this was captured and
stored but never actually reached the AI — `/api/analyze` and `/api/chat`
gave the same generic, industry-agnostic output to every user regardless
of what they'd answered. It's now wired through to both.

## What changed

- **`business_context.py`** — added `get_context_for_user(user_id)` and
  `get_context_for_session()` (plain dict in/out, no Flask
  request/response coupling — safe to call from deep inside an analysis
  loop) and `format_context_for_prompt(context)`, which turns a context
  dict into the text block the LLM actually sees. Label maps
  (`SECTOR_LABELS`, `DATA_SENSITIVITY_LABELS`, `COMPLIANCE_LABELS`,
  `AVAILABILITY_LABELS`) live here too, next to the schema they describe,
  so there's one source of truth for how each answer gets phrased to the
  model. `me()` now calls `get_context_for_user()` instead of duplicating
  the query.
- **`ai_analysis.py`** — `analyze(vuln, business_context=None)` takes an
  optional context dict. When present, it's appended to the grounded user
  prompt as its own `BUSINESS CONTEXT` section, and the system prompt
  gains one specific, bounded rule: a CVSS-based priority tier may be
  escalated **one tier** above what CVSS alone would justify when the
  finding is internet-facing AND the org's criticality tier is 1-2 (or
  the data involved is sensitive/regulated) — CVSS 9.0+ still always
  means P1/P2 regardless, and nothing here can push a finding below what
  its CVSS score would already justify. This is deliberately narrow: the
  goal is "let real business risk break ties and justify urgency", not
  "let the model freely re-invent severity."
- **`chatbot.py`** — `ask(..., business_context=None)` adds the same
  formatted block to its system prompt, with an instruction to weigh it
  specifically for prioritisation-flavored questions ("what should we fix
  first") rather than defaulting to a pure severity sort.
- **`scanner.py`** — both `/api/analyze` and `/api/chat` now call
  `get_context_for_session()` once per request and pass it through.
  Anonymous sessions and users who haven't completed the questionnaire
  get `None`, which produces byte-for-byte the same output as before this
  feature existed — nothing breaks for them.

## The cache bug this could have caused (and how it's avoided)

`OllamaVulnerabilityAnalyzer` is a **process-wide singleton** shared
across every user's requests (`scanner.py`'s `_get_analyzer()`). Its
per-CVE result cache existed before business context did. Naively adding
context to the prompt without touching the cache key would have meant:
the first user to analyze `CVE-2024-XXXX` "wins," and every other user —
regardless of their own sector, compliance scope, or criticality — gets
that first user's business-context-flavored result served back to them
from cache. Wrong advice, and a mild cross-tenant data-shape leak (one
org's business profile implicitly shaping what another org sees).

Fixed: the cache key is now `(cve_or_title, context_fingerprint)`, where
`_context_fingerprint()` hashes every field of the context dict. Different
context (or no context) is a different cache entry. Verified in testing:
signed in as a healthcare/HIPAA org, the analyzer escalated a Medium-CVSS
finding to P1 and referenced the compliance exposure; a second session
signed in as a banking/PCI-DSS org analyzing the *same* CVE got its own
independently-computed result — no bleed-through either direction.

## Example: what the model actually sees

For a signed-in healthcare org (life-safety criticality, public-facing,
HIPAA in scope, no dedicated security team), the user prompt for
`/api/analyze` now includes:

```
BUSINESS CONTEXT for this organisation — factor this into severity reasoning,
remediation urgency, and how you phrase explanations and fixes. Do not ignore
it in favour of generic, industry-agnostic advice.
- Industry/sector: Healthcare
- Data handled by affected systems: medical records / PHI, personally identifiable information (PII)
- Business impact if unavailable: life-safety critical if unavailable (internal criticality tier 1/5, 1 = most critical)
- Internet exposure: public
- Compliance frameworks in scope: HIPAA
- No dedicated security team — prefer fixes an IT generalist can execute without
  specialist security tooling, and suggest compensating controls (e.g. network
  segmentation, WAF rules, disabling the affected feature) when immediate
  patching isn't realistic.
```

A banking/PCI-DSS org with a dedicated security team gets a differently
shaped block (different sector label, different compliance framework, and
the *opposite* security-team clause — deeper/more technical guidance
instead of generalist-friendly steps).

## Verifying it

No new endpoint was added for this — check it through the normal flow:
sign up, complete the questionnaire (`POST /api/business-context`), then
run `/api/analyze` or ask the chatbot "what should we fix first?" and
compare the `why` field / chat answer against what you get from a session
that skipped the questionnaire. The difference should be visible in
wording (compliance/sector-specific language) and, for borderline
findings, in `priority_tier`.

"""
AI analysis service — calls a local Ollama model to turn a normalized
vulnerability (shape produced by scanners/*.py) into the fields the
frontend already renders in CveDetailStep:

    confidence (int 0-100), why (str), business_impact (str), fixes (list[str])

Also returns priority_tier (P1-P4) for future use even though the current
UI doesn't display it yet.

Design mirrors the capstone's LLM-integration notes: grounded prompt
(never rely on the model's training memory for CVE facts), strict JSON
contract, retry with a simplified prompt on malformed output, template
fallback if both attempts fail, and a cache keyed by CVE ID (plus a
business-context signature, see _cache_key) so re-running the same scan
doesn't re-spend tokens/compute on unchanged findings.

Business context: if the signed-in user has completed the business-context
survey (business_context.py), scanner.py's /api/analyze endpoint passes
that record in here as `business_context` on every analyze() call. When
present, it's:
  1. Folded into the LLM prompt so "why"/"fixes"/"priority_tier" reason
     about *this org's* exposure (internet-facing? regulated data? a
     life-safety system?) instead of giving generic CVE commentary.
  2. Used to compute `business_priority_score`, a deterministic numeric
     score (see compute_business_priority_score) that blends CVSS/severity
     with business impact. This is what scanner.py sorts findings by, and
     it's computed independently of the LLM so ordering stays sane even
     when Ollama is unreachable and analyze() falls back to the template
     result below.

Previously called the Claude API — swapped to a local Ollama model. The
class does the same job so scanner.py's usage didn't need to change beyond
the import name; see ollama_client.py for the actual HTTP call.
"""
import json
import logging
import os

from ollama_client import chat as ollama_chat, OllamaError

logger = logging.getLogger(__name__)

MAX_RETRIES = int(os.getenv("AI_MAX_RETRIES", "2"))

SYSTEM_PROMPT = """You are a senior cybersecurity analyst producing a vulnerability triage write-up for a specific
organisation, not a generic CVE summary.
Rules:
- Only use the vulnerability data provided in the prompt. Do not speculate or invent CVEs, patches, or advisories not present in the input.
- Respond ONLY with a single JSON object, no preamble, no markdown code fences.
- The JSON object must have exactly these fields:
  "why" (string, 2-4 sentences, under 600 chars): explain the TECHNICAL mechanism of the vulnerability - what's
    broken, how an attacker would actually exploit it, and what they'd gain (RCE, data exposure, DoS, etc). Be
    specific using whatever detail the description/title gives you; don't just restate the severity label.
  "business_impact" (string, 2-4 sentences, under 600 chars): a SEPARATE paragraph translating the technical
    issue above into concrete consequences FOR THIS ORGANISATION. If a "Business context" section is present in
    the prompt, you MUST reference at least two of its specific details by name (e.g. name the sector, the exact
    compliance framework(s) like "PCI-DSS" or "HIPAA", the specific data types at risk like "cardholder data" or
    "medical records", the internet-facing/air-gapped status, or the criticality tier) rather than vague phrases
    like "this could be bad for your business". Explain WHY those specific details raise or lower the stakes -
    e.g. why internet-facing + regulated data compounds the risk, or why an air-gapped internal system narrows
    the realistic blast radius. If no "Business context" section is present in the prompt, set this to an empty
    string "" - do not invent business details that weren't provided.
  "fixes" (array of 2-4 short strings, concrete remediation steps an IT generalist can follow): when business
    context is provided, at least one entry should reflect it specifically - e.g. a compliance-driven
    documentation/reporting step for the named framework(s), a remediation timeline suited to the criticality
    tier, or a network segmentation step for an internet-facing or air-gapped system. Don't force this if it
    would be contrived; a technically-sound generic fix is better than a forced business reference.
  "confidence" (integer 0-100, how confident you are in this analysis given the completeness of the input data —
    lower it when the description or CVSS data is missing or thin),
  "priority_tier" (string, one of "P1", "P2", "P3", "P4" — P1 is most urgent). Anchor the tier to the input CVSS
    score first (don't assign P1/P2 below CVSS 7.0 unless the input notes a known public exploit; don't assign
    P3/P4 to CVSS 9.0+), then adjust by AT MOST ONE TIER in either direction if business context is provided and
    clearly warrants it — e.g. bump up for a life-safety or internet-facing system handling regulated data, or
    ease down for an internal, air-gapped system with no sensitive data. Explain that adjustment in
    "business_impact", not "why".
"""

_SIMPLIFIED_SYSTEM_PROMPT = """You are a cybersecurity analyst. Only use the data given.
Respond ONLY with JSON: {"why": "technical explanation of the vulnerability", "business_impact": "2-4 sentences on what this specifically means for this organisation, naming its sector/compliance/data/exposure details if a Business context section was given, else empty string", "fixes": ["...", "..."], "confidence": 0-100, "priority_tier": "P1|P2|P3|P4"}
No other text."""

_REQUIRED_FIELDS = {"why": str, "business_impact": str, "fixes": list, "confidence": int, "priority_tier": str}

SEVERITY_BASE_SCORE = {"Critical": 10.0, "High": 7.5, "Medium": 5.0, "Low": 2.5, "Unknown": 1.0}

# criticality_tier (1 = life-safety ... 5 = no impact, see business_context.py's
# AVAILABILITY_TO_TIER) -> multiplier applied to the base CVSS/severity score.
_TIER_MULTIPLIER = {1: 1.5, 2: 1.25, 3: 1.0, 4: 0.85, 5: 0.7}

_SENSITIVE_DATA_TYPES = {"credentials", "financial", "medical", "pii", "intellectual_property"}


def _business_context_signature(business_context: dict | None):
    """Compact, hashable summary of the fields that actually affect analysis
    output, used as part of the cache key so cached why/fixes/priority_tier
    text tailored to one org's context is never handed to a different org
    that happens to have a finding with the same CVE."""
    if not business_context:
        return None
    return (
        business_context.get("criticalityTier"),
        business_context.get("internetFacing"),
        business_context.get("airGapped"),
        tuple(sorted(business_context.get("dataSensitivity") or [])),
        tuple(sorted(business_context.get("complianceScope") or [])),
    )


def _business_context_prompt_block(business_context: dict) -> str:
    """Renders the survey answers as a short block appended to the user
    prompt. Kept factual/declarative (no instructions) since it's untrusted-
    ish user-entered data (e.g. sectorOther, airGappedDetails free text)
    being interpolated into the prompt."""
    sensitivity = ", ".join(business_context.get("dataSensitivity") or []) or "none reported"
    compliance = ", ".join(business_context.get("complianceScope") or []) or "none reported"
    lines = [
        "\nBusiness context for this organisation (weight your analysis accordingly):",
        f"- Sector: {business_context.get('sectorOther') or business_context.get('sector') or 'unspecified'}",
        f"- Business criticality tier: {business_context.get('criticalityTier')} (1=life-safety, 5=no impact)",
        f"- Data handled: {sensitivity}",
        f"- Compliance scope: {compliance}",
        f"- Internet-facing: {business_context.get('internetFacing')}",
        f"- Air-gapped systems present: {'yes' if business_context.get('airGapped') else 'no'}",
    ]
    return "\n".join(lines)


def compute_business_priority_score(vuln: dict, business_context: dict | None) -> float:
    """Deterministic score used to ORDER findings by business importance,
    not just CVE/CVSS score. Computed independently of the LLM so ranking
    stays meaningful even in the ai_generated=False template-fallback path.

    Higher = more important to remediate soon. With no business context
    (survey not completed) this collapses to a straightforward severity/
    CVSS score, so ordering degrades gracefully to today's CVSS-only sort.
    """
    cvss = vuln.get("cvss")
    base = float(cvss) if isinstance(cvss, (int, float)) else SEVERITY_BASE_SCORE.get(
        vuln.get("severity"), SEVERITY_BASE_SCORE["Unknown"]
    )

    if not business_context:
        return round(base, 2)

    score = base * _TIER_MULTIPLIER.get(business_context.get("criticalityTier"), 1.0)

    internet_facing = business_context.get("internetFacing")
    exposure_bonus = {"public": 1.5, "mixed": 0.75, "internal": 0.0}.get(internet_facing, 0.0)

    data_sensitivity = set(business_context.get("dataSensitivity") or [])
    if data_sensitivity & _SENSITIVE_DATA_TYPES:
        exposure_bonus += 1.0

    compliance_scope = business_context.get("complianceScope") or []
    if any(c != "none" for c in compliance_scope):
        exposure_bonus += 0.75

    # Air-gapped orgs have already told us these systems aren't reachable
    # from outside, so temper the internet/compliance exposure bump rather
    # than drop it entirely (compliance scope can still apply on an
    # air-gapped network).
    if business_context.get("airGapped"):
        exposure_bonus *= 0.5

    score *= (1 + exposure_bonus)
    return round(score, 2)


def _template_business_impact(business_context: dict | None, severity: str) -> str:
    """Deterministic stand-in for the LLM's business_impact paragraph, used
    only in the template-fallback path (Ollama unreachable/failed) so the
    UI still shows *something* tying the finding to the org's context
    instead of going blank. Not as nuanced as a real model write-up, but
    references the same concrete details the prompt would have."""
    if not business_context:
        return ""
    parts = []
    sector = business_context.get("sectorOther") or business_context.get("sector")
    if sector:
        parts.append(f"your {sector.replace('_', ' ')} environment")
    if business_context.get("internetFacing") == "public":
        parts.append("an internet-facing system")
    elif business_context.get("internetFacing") == "mixed":
        parts.append("a partially internet-facing system")
    sensitivity = [s for s in (business_context.get("dataSensitivity") or []) if s != "none"]
    if sensitivity:
        parts.append(f"data including {', '.join(sensitivity)}")
    compliance = [c for c in (business_context.get("complianceScope") or []) if c != "none"]
    if compliance:
        parts.append(f"scope under {', '.join(c.upper().replace('_', '-') for c in compliance)}")
    if not parts:
        return ""
    tier = business_context.get("criticalityTier")
    urgency = "elevated" if isinstance(tier, int) and tier <= 2 else "standard"
    return (
        f"For {', '.join(parts)}, a {severity or 'this'} severity finding like this carries {urgency} "
        f"business risk. (Automated fallback summary — AI analysis was unavailable for the full write-up.)"
    )


class OllamaVulnerabilityAnalyzer:
    """Renamed from ClaudeVulnerabilityAnalyzer — same interface (.analyze()),
    same return shape, now backed by a local Ollama model instead of the
    Claude API. Update imports elsewhere in the codebase if you see the old
    name."""

    def __init__(self, model: str = None):
        # No API key needed for a local Ollama instance — model/host are
        # read from OLLAMA_MODEL / OLLAMA_HOST (see ollama_client.py).
        # Errors surface per-call instead (server not running, model not
        # pulled, etc.) so a misconfigured Ollama doesn't crash the app at
        # import/construction time.
        self.model = model
        self._cache = {}

    def _build_user_prompt(self, vuln: dict, business_context: dict | None = None) -> str:
        """Grounded context only — CVE facts, no real hostnames (asset field
        here is already whatever the scanner's parse() produced, which for
        Trivy uploads is the scan target string, not a live hostname).
        Business context (from the sign-up survey), when available, is
        appended as its own clearly-labelled block."""
        lines = [
            f"CVE ID: {vuln.get('cve') or 'N/A (no CVE mapped, use title/description)'}",
            f"Title: {vuln.get('title', '')}",
            f"Description: {(vuln.get('description') or '')[:3000]}",
            f"CVSS score: {vuln.get('cvss') if vuln.get('cvss') is not None else 'unknown'}",
            f"Reported severity: {vuln.get('severity', 'Unknown')}",
        ]
        if vuln.get("package"):
            lines.append(f"Affected package: {vuln['package']} (installed: {vuln.get('installedVersion', 'unknown')})")
        prompt = "\n".join(lines)
        if business_context:
            prompt += "\n" + _business_context_prompt_block(business_context)
        return prompt

    def _call_ollama(self, system_prompt: str, user_prompt: str):
        try:
            text = ollama_chat(
                system_prompt,
                [{"role": "user", "content": user_prompt}],
                model=self.model,
                json_mode=True,
            )
        except OllamaError as e:
            logger.error("Ollama error: %s", e)
            return None

        text = text.strip()
        if text.startswith("```"):
            text = text.strip("`")
            if text.lower().startswith("json"):
                text = text.split("\n", 1)[-1]

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            logger.warning("Ollama response was not valid JSON: %s", text[:200])
            return None

        for field, expected_type in _REQUIRED_FIELDS.items():
            if field not in parsed or not isinstance(parsed[field], expected_type):
                logger.warning("Ollama response missing/invalid field: %s", field)
                return None
        if parsed["priority_tier"] not in ("P1", "P2", "P3", "P4"):
            return None

        return parsed

    @staticmethod
    def _severity_to_tier(severity: str) -> str:
        return {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4"}.get(severity, "P3")

    def analyze(self, vuln: dict, business_context: dict | None = None) -> dict:
        """
        Returns a dict with why/fixes/confidence/priority_tier/ai_generated/
        business_priority_score, ready to be merged into the vulnerability
        record (**vuln, **result).

        `business_context` is the record from business_context.py's
        get_business_context() for the signed-in user, or None if they
        haven't completed that survey (or aren't signed in) — in which case
        this behaves exactly as before, CVSS/severity only.
        """
        cve_or_title = vuln.get("cve") or vuln.get("title")
        cache_key = (cve_or_title, _business_context_signature(business_context)) if cve_or_title else None
        # business_priority_score doesn't depend on the LLM call at all, so
        # compute it fresh every time (cheap) rather than trusting a cached
        # value from a differently-scored vuln under the same cache key.
        business_priority_score = compute_business_priority_score(vuln, business_context)

        if cache_key and cache_key in self._cache:
            return {**self._cache[cache_key], "business_priority_score": business_priority_score, "from_cache": True}

        user_prompt = self._build_user_prompt(vuln, business_context)
        parsed = None

        for attempt in range(MAX_RETRIES + 1):
            parsed = self._call_ollama(SYSTEM_PROMPT, user_prompt)
            if parsed is not None:
                break
            logger.info("Retry %d/%d for %s", attempt + 1, MAX_RETRIES, cve_or_title)

        if parsed is None:
            parsed = self._call_ollama(_SIMPLIFIED_SYSTEM_PROMPT, user_prompt)

        if parsed is None:
            logger.warning("LLM analysis failed for %s — using template fallback", cve_or_title)
            result = {
                "why": vuln.get("description") or "Automated analysis unavailable for this finding.",
                "business_impact": _template_business_impact(business_context, vuln.get("severity")),
                "fixes": [
                    f"Upgrade {vuln['package']} beyond {vuln.get('installedVersion', 'the installed version')}"
                    if vuln.get("package") else "Review vendor advisory and apply the recommended patch.",
                    "Manual review required — AI analysis failed after retries.",
                ],
                "confidence": 30,
                "priority_tier": self._severity_to_tier(vuln.get("severity", "")),
                "ai_generated": False,
                "from_cache": False,
                "business_priority_score": business_priority_score,
            }
            return result

        result = {
            **parsed,
            "ai_generated": True,
            "from_cache": False,
            "business_priority_score": business_priority_score,
        }
        if cache_key:
            self._cache[cache_key] = result
        return result


# Backwards-compatible alias in case anything else still imports the old
# name — prefer OllamaVulnerabilityAnalyzer in new code.
ClaudeVulnerabilityAnalyzer = OllamaVulnerabilityAnalyzer

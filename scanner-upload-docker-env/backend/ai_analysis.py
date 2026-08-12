"""
AI analysis service — calls a local Ollama model to turn a normalized
vulnerability (shape produced by scanners/*.py) into the fields the
frontend already renders in CveDetailStep:

    confidence (int 0-100), why (str), fixes (list[str])

Also returns priority_tier (P1-P4) for future use even though the current
UI doesn't display it yet.

Design mirrors the capstone's LLM-integration notes: grounded prompt
(never rely on the model's training memory for CVE facts), strict JSON
contract, retry with a simplified prompt on malformed output, template
fallback if both attempts fail, and a cache keyed by CVE ID so re-running
the same scan doesn't re-spend tokens/compute on unchanged findings.

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

SYSTEM_PROMPT = """You are a cybersecurity analyst assisting with vulnerability triage.
Rules:
- Only use the vulnerability data provided in the prompt. Do not speculate or invent CVEs, patches, or advisories not present in the input.
- Respond ONLY with a single JSON object, no preamble, no markdown code fences.
- The JSON object must have exactly these fields:
  "why" (string, plain-language explanation of the vulnerability and why it matters, under 500 chars),
  "fixes" (array of 2-4 short strings, concrete remediation steps an IT generalist can follow),
  "confidence" (integer 0-100, how confident you are in this analysis given the completeness of the input data —
    lower it when the description or CVSS data is missing or thin),
  "priority_tier" (string, one of "P1", "P2", "P3", "P4" — P1 is most urgent, must be consistent with the input
    CVSS score: don't assign P1/P2 below CVSS 7.0 unless the input notes a known public exploit; don't assign
    P3/P4 to CVSS 9.0+).
"""

_SIMPLIFIED_SYSTEM_PROMPT = """You are a cybersecurity analyst. Only use the data given.
Respond ONLY with JSON: {"why": "...", "fixes": ["...", "..."], "confidence": 0-100, "priority_tier": "P1|P2|P3|P4"}
No other text."""

_REQUIRED_FIELDS = {"why": str, "fixes": list, "confidence": int, "priority_tier": str}


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

    def _build_user_prompt(self, vuln: dict) -> str:
        """Grounded context only — CVE facts, no real hostnames (asset field
        here is already whatever the scanner's parse() produced, which for
        Trivy uploads is the scan target string, not a live hostname)."""
        lines = [
            f"CVE ID: {vuln.get('cve') or 'N/A (no CVE mapped, use title/description)'}",
            f"Title: {vuln.get('title', '')}",
            f"Description: {(vuln.get('description') or '')[:3000]}",
            f"CVSS score: {vuln.get('cvss') if vuln.get('cvss') is not None else 'unknown'}",
            f"Reported severity: {vuln.get('severity', 'Unknown')}",
        ]
        if vuln.get("package"):
            lines.append(f"Affected package: {vuln['package']} (installed: {vuln.get('installedVersion', 'unknown')})")
        return "\n".join(lines)

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

    def analyze(self, vuln: dict) -> dict:
        """
        Returns a dict with why/fixes/confidence/priority_tier/ai_generated,
        ready to be merged into the vulnerability record (**vuln, **result).
        """
        cache_key = vuln.get("cve") or vuln.get("title")
        if cache_key and cache_key in self._cache:
            return {**self._cache[cache_key], "from_cache": True}

        user_prompt = self._build_user_prompt(vuln)
        parsed = None

        for attempt in range(MAX_RETRIES + 1):
            parsed = self._call_ollama(SYSTEM_PROMPT, user_prompt)
            if parsed is not None:
                break
            logger.info("Retry %d/%d for %s", attempt + 1, MAX_RETRIES, cache_key)

        if parsed is None:
            parsed = self._call_ollama(_SIMPLIFIED_SYSTEM_PROMPT, user_prompt)

        if parsed is None:
            logger.warning("LLM analysis failed for %s — using template fallback", cache_key)
            result = {
                "why": vuln.get("description") or "Automated analysis unavailable for this finding.",
                "fixes": [
                    f"Upgrade {vuln['package']} beyond {vuln.get('installedVersion', 'the installed version')}"
                    if vuln.get("package") else "Review vendor advisory and apply the recommended patch.",
                    "Manual review required — AI analysis failed after retries.",
                ],
                "confidence": 30,
                "priority_tier": self._severity_to_tier(vuln.get("severity", "")),
                "ai_generated": False,
                "from_cache": False,
            }
            return result

        result = {**parsed, "ai_generated": True, "from_cache": False}
        if cache_key:
            self._cache[cache_key] = result
        return result


# Backwards-compatible alias in case anything else still imports the old
# name — prefer OllamaVulnerabilityAnalyzer in new code.
ClaudeVulnerabilityAnalyzer = OllamaVulnerabilityAnalyzer

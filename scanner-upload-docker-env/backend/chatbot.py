"""
Scan-scoped chatbot — answers questions about the vulnerabilities in the
current scan/report ("which CVEs affect host X", "what's our most severe
finding", etc.).

Grounded the same way as ai_analysis.py: the full current finding list is
included in every call as context, and the model is told not to reference
anything outside it. This is deliberately NOT a general security assistant —
it only knows what's in the scan you hand it.

Previously called the Claude API — swapped to a local Ollama model via
ollama_client.py. Interface (.ask()) is unchanged.
"""
import logging
import os

from ollama_client import chat as ollama_chat

logger = logging.getLogger(__name__)

CHAT_MAX_CONTEXT_VULNS = int(os.getenv("CHAT_MAX_CONTEXT_VULNS", "300"))  # cap prompt size for very large scans
MAX_HISTORY_TURNS = 6

SYSTEM_PROMPT_TEMPLATE = """You are a security analyst assistant embedded in a vulnerability scanning dashboard.
Answer the user's question using ONLY the vulnerability data below, from their current scan/report.

Rules:
- Do not reference any CVE, host, or package that is not listed below.
- If the question can't be answered from this data, say so plainly instead of guessing.
- Be concise: a few sentences or a short list, not a report.
- When asked "which CVEs affect host X" or similar, list matching CVE IDs with severity.
- When asked for a count or "how many", give the exact number from the data below.

Current scan data ({count} findings):
{context}
"""


class ScanChatbot:
    def __init__(self, model: str = None):
        # No API key needed for a local Ollama instance — see ollama_client.py
        # for OLLAMA_HOST / OLLAMA_MODEL configuration.
        self.model = model

    @staticmethod
    def _build_context(vulnerabilities: list) -> str:
        lines = []
        for v in vulnerabilities[:CHAT_MAX_CONTEXT_VULNS]:
            cve = v.get("cve") or v.get("title") or "Unknown"
            lines.append(
                f"- {cve} | title={v.get('title', '')} | severity={v.get('severity', 'Unknown')} | "
                f"cvss={v.get('cvss', 'unknown')} | asset={v.get('asset', 'unknown')} | "
                f"package={v.get('package', 'n/a')}"
            )
        if len(vulnerabilities) > CHAT_MAX_CONTEXT_VULNS:
            lines.append(
                f"... and {len(vulnerabilities) - CHAT_MAX_CONTEXT_VULNS} more findings not shown "
                f"(truncated for prompt size)."
            )
        return "\n".join(lines) if lines else "(no findings in this scan)"

    def ask(self, question: str, vulnerabilities: list, history: list = None) -> str:
        """
        question: the user's latest message
        vulnerabilities: the current scan's normalized findings (same shape
            used everywhere else in this app)
        history: optional prior turns, [{"role": "user"|"assistant", "content": "..."}]

        Raises OllamaError on failure (e.g. server unreachable, model not
        pulled) — scanner.py's /api/chat route catches this and returns a
        502 with the message, same as it did for Claude API errors before.
        """
        context = self._build_context(vulnerabilities or [])
        system_prompt = SYSTEM_PROMPT_TEMPLATE.format(count=len(vulnerabilities or []), context=context)

        messages = []
        for turn in (history or [])[-MAX_HISTORY_TURNS:]:
            role = turn.get("role")
            content = turn.get("content")
            if role in ("user", "assistant") and content:
                messages.append({"role": role, "content": content})
        messages.append({"role": "user", "content": question})

        return ollama_chat(system_prompt, messages, model=self.model)

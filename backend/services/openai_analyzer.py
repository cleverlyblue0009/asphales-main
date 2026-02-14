"""OpenAI integration for detailed phishing threat explanations."""

import json
import os
from typing import Optional

from utils.logger import setup_logger

logger = setup_logger("openai_analyzer")

SYSTEM_PROMPT = """You are a phishing detection expert. When given a suspicious phrase from a message, provide a specific, non-generic explanation of why it is dangerous.

Use examples like:
- "Real lotteries don't contact winners via unsolicited messages"
- "Real banks never ask for OTP or CVV via messages"
- "Legitimate government agencies don't threaten immediate arrest"
- "Authentic platforms won't ask you to verify account with personal details"

Be specific to the actual threat pattern, not generic. Respond ONLY with valid JSON in this format:
{
  "reason": "specific explanation why this is dangerous",
  "severity": "high|medium|low",
  "recommendation": "what user should do"
}"""


class OpenAIAnalyzer:
    """Uses OpenAI API to provide detailed phishing explanations."""

    def __init__(self):
        self.api_key: Optional[str] = os.getenv("OPENAI_API_KEY")
        self.enabled: bool = os.getenv("ENABLE_OPENAI", "true").lower() == "true"
        self.timeout: int = int(os.getenv("OPENAI_TIMEOUT", "3"))
        self.model: str = "gpt-4-mini"
        self.client: Optional[object] = None

        if self.api_key and self.enabled:
            try:
                from openai import OpenAI

                self.client = OpenAI(api_key=self.api_key, timeout=self.timeout)
                logger.info("OpenAI analyzer initialized")
            except ImportError:
                logger.warning("OpenAI package not installed")
        else:
            logger.warning(
                "OpenAI analyzer disabled — %s",
                "no API key" if not self.api_key else "disabled by config",
            )

    def is_available(self) -> bool:
        """Check whether the OpenAI analyzer can be used."""
        return self.client is not None and self.enabled

    def analyze_threat(
        self, phrase: str, category: str
    ) -> Optional[dict[str, str]]:
        """Get detailed explanation for a threat phrase.

        Returns dict with 'reason', 'severity', and 'recommendation' or None on failure.
        """
        if not self.is_available():
            logger.debug("OpenAI not available, skipping analysis")
            return None

        try:
            user_prompt = f"""Analyze this suspicious message phrase and explain why it's a phishing threat:

Phrase: "{phrase}"
Category: {category}

Provide specific reasons why this is dangerous, not generic warnings."""

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=200,
                temperature=0.3,
            )

            raw = response.choices[0].message.content.strip()

            # Strip markdown if present
            if raw.startswith("```"):
                lines = raw.split("\n")
                raw = "\n".join(lines[1:-1]) if len(lines) > 2 else raw

            result = json.loads(raw)
            logger.info("OpenAI analysis complete — severity=%s", result.get("severity"))
            return self._validate(result)

        except json.JSONDecodeError as exc:
            logger.error("Failed to parse OpenAI response as JSON: %s", exc)
            return None
        except Exception as exc:
            logger.error("OpenAI analysis failed: %s", exc)
            return None

    def _validate(self, result: dict) -> Optional[dict]:
        """Ensure the OpenAI response has the expected fields."""
        required = {"reason", "severity", "recommendation"}
        if not required.issubset(result.keys()):
            logger.warning("OpenAI response missing fields: %s", required - result.keys())
            return None

        severity = result["severity"]
        if severity not in ("high", "medium", "low"):
            logger.warning("Invalid severity from OpenAI: %s", severity)
            return None

        return result

"""OpenAI integration for detailed phishing threat explanations."""

import json
import os
from typing import Optional

from utils.logger import setup_logger

logger = setup_logger("openai_analyzer")

SYSTEM_PROMPT = """You are a phishing detection expert specializing in multilingual financial fraud and social engineering attacks. When given a suspicious phrase, explain SPECIFICALLY why it's dangerous by contrasting it with how REAL institutions actually operate.

Real Institution Facts:
BANKING: Real banks NEVER ask for OTP, CVV, PIN, or account passwords via SMS/messaging/email. They verify you through secure authenticated apps. Account blocks are handled through official channels only.

GOVERNMENT: Real government agencies send official notices through registered post or official portals, never demand immediate payment threats, never ask for personal documents via messages.

PAYMENTS/UPI: Real payment apps show money received/pending through authenticated notifications only. They never ask you to "click links" or "verify payment" after it's already processed.

LOTTERY/GRANTS: Real lotteries/government schemes you didn't enter don't contact you. Unsolicited "you won" messages are 100% scams.

JOBS: Real companies don't ask for money upfront, don't verify through messages, don't demand credentials instantly. Legit job offers come with official communication.

Be specific about which institution would NEVER do this. Respond ONLY with valid JSON:
{
  "reason": "Why this specific phrase is dangerous - mention how real institutions work differently",
  "what_real_institutions_do": "How legitimate versions of this organization actually handle this situation",
  "severity": "high|medium|low",
  "recommendation": "Specific action user should take"
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

        Returns dict with 'reason', 'severity', 'what_real_institutions_do', and 'recommendation' or None on failure.
        """
        if not self.is_available():
            logger.debug("OpenAI not available, skipping analysis")
            return None

        try:
            category_context = self._get_category_context(category)
            user_prompt = f"""Analyze this suspicious message phrase and explain why it's dangerous by contrasting with how REAL institutions work:

Phrase: "{phrase}"
Detected Category: {category}
{category_context}

Provide:
1. Why this specific phrase is dangerous (not generic)
2. How legitimate institutions handle this differently
3. Specific action the user should take"""

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=280,
                temperature=0.2,
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

    def _get_category_context(self, category: str) -> str:
        """Provide contextual hints based on detected threat category."""
        contexts = {
            "otp": "This mentions OTP/PIN/password - Real banks NEVER ask for these via messages.",
            "kyc": "This mentions KYC/verification - Real institutions verify through secure portals, not messages.",
            "payment": "This mentions payment/money transfer - Real apps confirm through authenticated interfaces only.",
            "urgent": "This creates false urgency/threat - Real institutions don't rush you into decisions via messages.",
            "link": "This asks to click a link - Real institutions send verified links only through official apps/portals.",
            "credential": "This asks for login credentials - Real services NEVER ask for passwords or personal pins.",
            "genai_detected": "AI detected social engineering pattern - Be suspicious of unexpected requests.",
            "ml_detected": "ML model flagged suspicious patterns - Exercise caution.",
            "ml_line_detected": "This line shows phishing indicators - Verify before taking action.",
            "fear": "This uses fear tactics - Real institutions don't threaten via messages.",
            "lottery": "This claims you won something unsolicited - This is almost always a scam.",
            "job": "This offers a job opportunity unsolicited - Real employers don't ask for money upfront.",
        }
        return f"Threat context: {contexts.get(category, 'General phishing pattern detected.')}"

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

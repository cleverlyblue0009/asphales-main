"""Google Gemini integration for threat detection and detailed explanations."""

import json
import os
from typing import Optional

from utils.logger import setup_logger

logger = setup_logger("gemini_analyzer")

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

THREAT_DETECTION_SYSTEM_PROMPT = """You are an expert in detecting phishing, scams, and social engineering attacks in text messages, emails, and online communications. Your task is to analyze text and identify ALL phishing/scam indicators.

PHISHING INDICATORS YOU MUST DETECT:
1. OTP/PASSWORD REQUESTS: Messages asking for OTP, CVV, PIN, passwords, 2FA codes
2. KYC/VERIFICATION: Requests for personal documents, identity verification, account updates
3. URGENCY/THREATS: Time-sensitive demands, account closure threats, immediate action required
4. CREDENTIAL HARVESTING: Fake login links, "verify account", "confirm identity"
5. PAYMENT SCAMS: Unexpected refunds, payment failures, pending payments, money requests
6. LOTTERY/PRIZE SCAMS: You won something you didn't enter, claim free rewards
7. JOB SCAMS: Unsolicited job offers, advance payment for jobs, fake recruitment
8. IMPERSONATION: Pretending to be banks, govt agencies, payment apps, employers
9. SUSPICIOUS LINKS: Shortened URLs, phishing domains, malicious links
10. SOCIAL ENGINEERING: Creating panic, fear, false authority, fake urgency

For EACH suspicious phrase or threat indicator found, respond with this JSON:
{
  "risk_score": 0-100,
  "is_phishing": true/false,
  "threats": [
    {
      "phrase": "exact suspicious text from message",
      "risk": 0-100,
      "category": "otp|kyc|credential|urgent|payment|lottery|job|impersonation|link|social_engineering",
      "explanation": "Why this is dangerous - be specific to what was detected"
    }
  ],
  "overall_assessment": "Brief summary of the threat level",
  "tactics": ["list", "of", "detected", "scam", "tactics"]
}

IMPORTANT RULES:
- Be thorough and find ALL suspicious indicators
- Give specific, actionable explanations
- Risk scores: 0-30=low, 30-60=medium, 60-85=high, 85-100=critical
- If clean/safe, return is_phishing=false with risk_score=0
- Always respond with valid JSON only"""


class GeminiAnalyzer:
    """Uses Google Gemini API to provide detailed phishing explanations."""

    def __init__(self):
        self.api_key: Optional[str] = os.getenv("GEMINI_API_KEY")
        self.enabled: bool = os.getenv("ENABLE_GEMINI", "true").lower() == "true"
        self.model: str = "gemini-1.5-flash"
        self.client: Optional[object] = None

        if self.api_key and self.enabled:
            try:
                import google.generativeai as genai

                genai.configure(api_key=self.api_key)
                self.client = genai
                logger.info("Gemini analyzer initialized with model %s", self.model)
            except ImportError:
                logger.warning("google-generativeai package not installed")
        else:
            logger.warning(
                "Gemini analyzer disabled — %s",
                "no API key" if not self.api_key else "disabled by config",
            )

    def is_available(self) -> bool:
        """Check whether the Gemini analyzer can be used."""
        return self.client is not None and self.enabled

    async def detect_threats(self, text: str) -> Optional[dict]:
        """Detect and score all phishing threats in text using Gemini.

        Returns dict with 'risk_score', 'is_phishing', 'threats', 'tactics' or None on failure.
        """
        if not self.is_available():
            logger.debug("Gemini not available, skipping threat detection")
            return None

        if not text or len(text.strip()) < 5:
            return {
                "risk_score": 0,
                "is_phishing": False,
                "threats": [],
                "overall_assessment": "Text too short for analysis",
                "tactics": [],
            }

        try:
            model = self.client.GenerativeModel(self.model)

            user_prompt = f"{THREAT_DETECTION_SYSTEM_PROMPT}\n\nAnalyze this text for phishing/scam indicators:\n\n{text}"

            response = model.generate_content(
                user_prompt,
                generation_config=self.client.types.GenerationConfig(
                    max_output_tokens=1200,
                    temperature=0.1,
                ),
            )

            raw = response.text.strip()

            # Strip markdown if present
            if raw.startswith("```"):
                lines = raw.split("\n")
                raw = "\n".join(lines[1:-1]) if len(lines) > 2 else raw

            result = json.loads(raw)
            logger.info(
                "Gemini threat detection complete — risk=%d, phishing=%s",
                result.get("risk_score", 0),
                result.get("is_phishing", False),
            )
            return self._validate_threat_result(result)

        except json.JSONDecodeError as exc:
            logger.error("Failed to parse Gemini threat response as JSON: %s", exc)
            return None
        except Exception as exc:
            logger.error("Gemini threat detection failed: %s", exc)
            return None

    def analyze_threat(
        self, phrase: str, category: str
    ) -> Optional[dict[str, str]]:
        """Get detailed explanation for a threat phrase.

        Returns dict with 'reason', 'severity', 'what_real_institutions_do', and 'recommendation' or None on failure.
        """
        if not self.is_available():
            logger.debug("Gemini not available, skipping analysis")
            return None

        try:
            category_context = self._get_category_context(category)
            user_prompt = f"""{SYSTEM_PROMPT}

Analyze this suspicious message phrase and explain why it's dangerous by contrasting with how REAL institutions work:

Phrase: "{phrase}"
Detected Category: {category}
{category_context}

Provide:
1. Why this specific phrase is dangerous (not generic)
2. How legitimate institutions handle this differently
3. Specific action the user should take"""

            model = self.client.GenerativeModel(self.model)
            response = model.generate_content(
                user_prompt,
                generation_config=self.client.types.GenerationConfig(
                    max_output_tokens=280,
                    temperature=0.2,
                ),
            )

            raw = response.text.strip()

            # Strip markdown if present
            if raw.startswith("```"):
                lines = raw.split("\n")
                raw = "\n".join(lines[1:-1]) if len(lines) > 2 else raw

            result = json.loads(raw)
            logger.info("Gemini analysis complete — severity=%s", result.get("severity"))
            return self._validate(result)

        except json.JSONDecodeError as exc:
            logger.error("Failed to parse Gemini response as JSON: %s", exc)
            return None
        except Exception as exc:
            logger.error("Gemini analysis failed: %s", exc)
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

    def _validate_threat_result(self, result: dict) -> Optional[dict]:
        """Ensure the threat detection response has required fields."""
        required = {"risk_score", "is_phishing", "threats"}
        if not required.issubset(result.keys()):
            logger.warning("Gemini threat response missing fields: %s", required - result.keys())
            return None

        risk_score = result.get("risk_score", 0)
        if not isinstance(risk_score, (int, float)) or risk_score < 0 or risk_score > 100:
            logger.warning("Invalid risk_score from Gemini: %s", risk_score)
            result["risk_score"] = max(0, min(100, int(risk_score) if isinstance(risk_score, (int, float)) else 0))

        if not isinstance(result.get("is_phishing"), bool):
            result["is_phishing"] = risk_score >= 30

        if not isinstance(result.get("threats"), list):
            result["threats"] = []

        return result

    def _validate(self, result: dict) -> Optional[dict]:
        """Ensure the Gemini response has the expected fields."""
        required = {"reason", "severity", "recommendation"}
        if not required.issubset(result.keys()):
            logger.warning("Gemini response missing fields: %s", required - result.keys())
            return None

        severity = result["severity"]
        if severity not in ("high", "medium", "low"):
            logger.warning("Invalid severity from Gemini: %s", severity)
            return None

        return result

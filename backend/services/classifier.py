"""Phishing classifier combining ML scoring + GenAI explanation."""

import time
from typing import Optional

from models.risk_scorer import RiskResult, RiskScorer, ThreatDetail
from services.cache_manager import CacheManager
from services.genai_analyzer import GenAIAnalyzer
from services.ml_classifier import MLPhishingClassifier
from services.openai_analyzer import OpenAIAnalyzer
from utils.logger import setup_logger
from utils.text_processor import text_hash, validate_length, detect_language, get_detected_scripts

logger = setup_logger("classifier")


class HybridClassifier:
    """ML-first classifier with line-level risk aggregation and optional GenAI reasoning."""

    def __init__(self):
        self.risk_scorer = RiskScorer()
        self.genai = GenAIAnalyzer()
        self.openai = OpenAIAnalyzer()
        self.ml = MLPhishingClassifier()
        self.cache = CacheManager(max_size=1000, ttl=60)

        self.total_requests = 0
        self.total_time_ms = 0.0

        logger.info(
            "Classifier ready — OpenAI (primary) %s, GenAI (secondary) %s, ML fallback %s",
            "enabled" if self.openai.is_available() else "disabled",
            "enabled" if self.genai.is_available() else "disabled",
            "available",
        )

    async def classify(self, text: str) -> RiskResult:
        self.total_requests += 1
        start = time.time()

        valid, _ = validate_length(text)
        if not valid:
            return RiskResult(
                overall_risk=0,
                severity="low",
                threats=[],
                method="error",
                processing_time_ms=0,
            )

        key = text_hash(text)
        cached = self.cache.get(key)
        if cached is not None:
            elapsed = (time.time() - start) * 1000
            cached.processing_time_ms = elapsed
            cached.cached = True
            self.total_time_ms += elapsed
            return cached

        # Primary: Use OpenAI for threat detection
        openai_result = await self.openai.detect_threats(text)

        final_score = 0
        threats: list[ThreatDetail] = []
        method = "openai"

        if openai_result:
            final_score = openai_result.get("risk_score", 0)

            # Convert OpenAI threats to ThreatDetail objects
            for threat in openai_result.get("threats", []):
                threats.append(
                    ThreatDetail(
                        phrase=threat.get("phrase", text[:100]),
                        risk=threat.get("risk", final_score),
                        category=threat.get("category", "openai_detected"),
                        explanation=threat.get("explanation", "OpenAI ne phishing pattern detect kiya."),
                    )
                )
        else:
            # Fallback to ML if OpenAI fails
            logger.warning("OpenAI threat detection failed, falling back to ML")
            ml_doc_result = self.ml.predict(text)
            ml_doc_score = ml_doc_result["risk_score"]

            line_threats, max_line_score, critical_line = self._score_suspicious_lines(text)
            final_score = max(ml_doc_score, max_line_score)
            threats = line_threats
            method = "ml_fallback"

        severity = self.risk_scorer.get_severity(final_score)

        # Optional: Get GenAI second opinion if available and score is borderline
        genai_score: Optional[int] = None
        if self.genai.is_available() and 30 <= final_score <= 70:
            genai_result = await self.genai.analyze(text)
            if genai_result is not None:
                genai_score = int(genai_result["risk_score"])
                # If GenAI has higher confidence, adjust final score
                if genai_result.get("is_phishing"):
                    final_score = max(final_score, genai_score)
                    method = "openai+genai"

        severity = self.risk_scorer.get_severity(final_score)

        result = RiskResult(
            overall_risk=final_score,
            severity=severity,
            threats=threats[:8],
            method=method,
            ml_score=None,
            genai_score=genai_score,
            processing_time_ms=(time.time() - start) * 1000,
            critical_line=None,
        )

        self.total_time_ms += result.processing_time_ms
        self.cache.set(key, result)
        return result

    def _score_suspicious_lines(self, text: str) -> tuple[list[ThreatDetail], int, Optional[str]]:
        lines = [ln.strip() for ln in text.splitlines() if len(ln.strip()) >= 20]
        threats: list[ThreatDetail] = []
        max_line = 0
        critical_line: Optional[str] = None

        for line in lines:
            line_risk = self.ml.predict(line)["risk_score"]
            if line_risk > max_line:
                max_line = line_risk
                critical_line = line[:300]

            # Detect language for better vernacular handling
            lang = detect_language(line)
            is_vernacular = lang != "english" and lang != "multilingual"

            # Lower threshold for pure vernacular text to catch more phishing
            # since vernacular messages may have different patterns
            threshold = 45 if is_vernacular else 52

            if line_risk >= threshold:
                scripts = get_detected_scripts(line)
                script_info = f" [{', '.join(scripts)}]" if scripts else ""

                threats.append(
                    ThreatDetail(
                        phrase=line[:220],
                        risk=line_risk,
                        category="ml_line_detected",
                        explanation=f"Is line mein phishing-like pattern detected{script_info} (OTP/KYC/urgency/credential bait).",
                    )
                )

        deduped: dict[str, ThreatDetail] = {}
        for t in threats:
            deduped[t.phrase] = t
        sorted_threats = sorted(deduped.values(), key=lambda x: x.risk, reverse=True)
        return sorted_threats, max_line, critical_line

    async def batch_classify(self, texts: list[str]) -> list[RiskResult]:
        return [await self.classify(text) for text in texts]

    def get_stats(self) -> dict:
        avg_time = self.total_time_ms / self.total_requests if self.total_requests else 0.0
        return {
            "total_requests": self.total_requests,
            "avg_response_time_ms": round(avg_time, 1),
            "genai_available": self.genai.is_available(),
            "ml": self.ml.get_info(),
            "cache": self.cache.stats(),
        }

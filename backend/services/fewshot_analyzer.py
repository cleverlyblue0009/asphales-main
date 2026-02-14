"""Few-shot learning analyzer using real phishing examples from dataset."""

import json
import os
import re
import csv
from typing import Optional, List, Dict
import httpx

from utils.logger import setup_logger

logger = setup_logger("fewshot_analyzer")


class FewShotAnalyzer:
    """Uses few-shot learning with real phishing examples."""

    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY")
        self.enabled = os.getenv("ENABLE_GROQ", "true").lower() == "true"
        self.api_url = "https://api.groq.com/openai/v1/chat/completions"
        self.model = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
        
        # Load training examples
        self.examples = self._load_examples()
        
        if self.api_key and self.enabled:
            logger.info("Few-shot analyzer initialized with %d examples", len(self.examples))
        else:
            logger.warning("Groq disabled")

    def _load_examples(self) -> List[Dict]:
        """Load phishing examples from CSV."""
        examples = []
        
        # Try multiple possible paths
        possible_paths = [
            "data/phishing_multilingual_vernacular_22lang.csv",
            "backend/data/phishing_multilingual_vernacular_22lang.csv",
            "../data/phishing_multilingual_vernacular_22lang.csv",
            "/mnt/user-data/uploads/phishing_multilingual_vernacular_22lang.csv",
        ]
        
        csv_path = None
        for path in possible_paths:
            if os.path.exists(path):
                csv_path = path
                break
        
        if not csv_path:
            logger.warning("Could not find phishing dataset CSV in any expected location")
            return examples
        
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get('label') == '1':  # Phishing only
                        examples.append({
                            "text": row.get('text', '').strip(),
                            "language": row.get('language', 'Unknown'),
                            "category": row.get('category', 'unknown'),
                        })
            
            logger.info("Loaded %d phishing examples from %s", len(examples), csv_path)
        except Exception as e:
            logger.warning("Could not load examples: %s", e)
        
        return examples

    def _build_few_shot_prompt(self) -> str:
        """Build system prompt with few-shot examples."""
        
        # Select diverse examples (max 15 to fit in context)
        selected = []
        languages_seen = set()
        
        for ex in self.examples:
            lang = ex['language']
            if lang not in languages_seen and len(selected) < 15:
                selected.append(ex)
                languages_seen.add(lang)
        
        # Build prompt with examples
        prompt = """You are a phishing detection expert. You have been trained on these REAL phishing messages:

TRAINING EXAMPLES (These are ALL phishing - label=1):

"""
        
        for i, ex in enumerate(selected, 1):
            prompt += f"""
Example {i} ({ex['language']} - {ex['category']}):
Text: "{ex['text']}"
This is PHISHING with risk 95-100.

"""
        
        prompt += """
NOW ANALYZE THE USER'S MESSAGE:

RULES:
1. Extract COMPLETE sentences like the examples above
2. For pure vernacular (Hindi/Tamil/Telugu/Bengali/Marathi/Gujarati), extract the FULL paragraph
3. Include URLs with surrounding context (100+ chars before/after)
4. Mark risk 90-100 for messages similar to training examples
5. Look for: OTP requests, KYC demands, account threats, urgent language, suspicious links

RESPONSE FORMAT (JSON only):
{
  "risk_score": 0-100,
  "is_phishing": true/false,
  "threats": [
    {
      "phrase": "COMPLETE SENTENCE/PARAGRAPH from the message",
      "risk": 0-100,
      "category": "otp|kyc|credential|urgent|payment|link",
      "explanation": "Why this is phishing (reference similar training examples)",
      "language": "detected language"
    }
  ],
  "overall_assessment": "Summary",
  "tactics": ["tactics", "used"]
}

CRITICAL: Messages in pure vernacular scripts (like the training examples) are HIGH PRIORITY. Extract full paragraphs!"""
        
        return prompt

    def is_available(self) -> bool:
        return True

    async def detect_threats(self, text: str) -> Optional[dict]:
        """Detect threats using few-shot learning."""
        if not text or len(text.strip()) < 5:
            return {
                "risk_score": 0,
                "is_phishing": False,
                "threats": [],
                "overall_assessment": "Text too short",
                "tactics": [],
            }

        logger.info("Analyzing %d characters with few-shot learning", len(text))
        
        # Try Groq with few-shot examples
        if self.api_key and self.enabled and self.examples:
            result = await self._groq_analyze(text)
            if result:
                return result
        
        # Fallback
        logger.info("Using pattern fallback")
        return self._pattern_fallback(text)

    async def _groq_analyze(self, text: str) -> Optional[dict]:
        """Use Groq with few-shot learning."""
        try:
            system_prompt = self._build_few_shot_prompt()
            
            async with httpx.AsyncClient(timeout=45.0) as client:
                messages = [
                    {"role": "system", "content": system_prompt},
                    {
                        "role": "user",
                        "content": f"Analyze this message for phishing. Compare with training examples:\n\n{text}"
                    }
                ]

                response = await client.post(
                    self.api_url,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": messages,
                        "temperature": 0.1,
                        "max_tokens": 2000,
                        "response_format": {"type": "json_object"},
                    },
                )
                
                if response.status_code != 200:
                    logger.error("Groq error: %d", response.status_code)
                    return None

                data = response.json()
                content = data["choices"][0]["message"]["content"]
                result = json.loads(content)
                
                logger.info("Few-shot analysis: %d threats, risk=%d", 
                           len(result.get("threats", [])), 
                           result.get("risk_score", 0))
                
                # Validate
                if not isinstance(result.get("threats"), list):
                    result["threats"] = []
                if not isinstance(result.get("risk_score"), (int, float)):
                    result["risk_score"] = 0
                if not isinstance(result.get("is_phishing"), bool):
                    result["is_phishing"] = result["risk_score"] >= 30
                
                return result

        except Exception as exc:
            logger.error("Groq failed: %s", exc)
            return None

    def _pattern_fallback(self, text: str) -> dict:
        """Pattern-based fallback using dataset keywords."""
        threats = []
        risk_score = 0
        
        # Extract keywords from training examples
        phishing_keywords = {
            "Hindi": ['बंद', 'तुरंत', 'ओटीपी', 'खाता', 'सत्यापन', 'KYC', 'आधार', 'कार्ड', 'विवरण'],
            "Bengali": ['বন্ধ', 'তাৎক্ষণিক', 'যাচাই', 'কার্ড', 'OTP'],
            "Tamil": ['தடை', 'உடனே', 'சரிபார்', 'கணக்கு', 'OTP'],
            "Marathi": ['बंद', 'तुरंत', 'सत्यापन', 'खाता'],
            "Gujarati": ['બ્લોક', 'તુરંત', 'ચકાસણી', 'ખાતો'],
            "Telugu": ['బ్లాక్', 'వెంటనే', 'ధృవీకరించండి'],
        }
        
        # Find vernacular blocks with phishing keywords
        for lang, keywords in phishing_keywords.items():
            for keyword in keywords:
                if keyword in text:
                    # Find the block containing this keyword
                    idx = text.find(keyword)
                    start = max(0, idx - 150)
                    end = min(len(text), idx + 200)
                    
                    # Extend to sentence boundaries
                    for delim in ['।', '.', '\n\n']:
                        delim_before = text.rfind(delim, start, idx)
                        if delim_before != -1:
                            start = delim_before + 1
                            break
                    
                    for delim in ['।', '.', '\n\n']:
                        delim_after = text.find(delim, idx, end)
                        if delim_after != -1:
                            end = delim_after + 1
                            break
                    
                    phrase = text[start:end].strip()
                    
                    if len(phrase) > 30:  # Minimum length
                        threats.append({
                            "phrase": phrase,
                            "risk": 90,
                            "category": "urgent",
                            "explanation": f"{lang} phishing detected - matches training examples with keyword '{keyword}'",
                            "language": lang
                        })
                        risk_score = max(risk_score, 90)
                        break  # One per language
        
        # URLs
        for match in re.finditer(r'https?://[^\s]+', text):
            url = match.group(0)
            start = max(0, match.start() - 200)
            end = min(len(text), match.end() + 100)
            context = text[start:end].strip()
            
            threats.append({
                "phrase": context,
                "risk": 85,
                "category": "link",
                "explanation": f"Phishing URL: {url}",
                "language": "Mixed"
            })
            risk_score = max(risk_score, 85)
        
        if threats:
            risk_score = min(100, risk_score + len(threats) * 5)
        
        return {
            "risk_score": risk_score,
            "is_phishing": risk_score >= 30,
            "threats": threats,
            "overall_assessment": f"Found {len(threats)} threats" if threats else "No threats",
            "tactics": list(set([t["category"] for t in threats])),
        }

    async def analyze_threat(self, phrase: str, category: str) -> Optional[dict]:
        """Detailed threat explanation."""
        # Find similar example from training
        similar = None
        for ex in self.examples:
            if category in ex.get('category', '').lower():
                similar = ex
                break
        
        explanation = f"This {category} message is phishing."
        if similar:
            explanation += f" Similar to: '{similar['text'][:50]}...' ({similar['language']})"
        
        return {
            "reason": explanation,
            "severity": "high",
            "what_real_institutions_do": "Real institutions never ask for OTP/credentials via messages.",
            "recommendation": "Do not respond. Contact institution directly using official number."
        }


# Backward compatibility
GeminiAnalyzer = FewShotAnalyzer
"""
Advanced vernacular phishing detection with robust fallback.
Designed specifically for pure Hindi/Tamil/Telugu/Bengali/Marathi/Gujarati detection.
"""

import json
import os
import re
import csv
import unicodedata
from typing import Optional, List, Dict
import httpx

from utils.logger import setup_logger

logger = setup_logger("vernacular_analyzer")


class VernacularPhishingAnalyzer:
    """Detects pure vernacular phishing with full sentence/paragraph extraction."""

    # Unicode ranges for Indian languages
    SCRIPT_RANGES = {
        "Hindi": (0x0900, 0x097F),      # Devanagari
        "Marathi": (0x0900, 0x097F),    # Devanagari
        "Sanskrit": (0x0900, 0x097F),   # Devanagari
        "Bengali": (0x0980, 0x09FF),
        "Assamese": (0x0980, 0x09FF),
        "Odia": (0x0B00, 0x0B7F),
        "Punjabi": (0x0A00, 0x0A7F),    # Gurmukhi
        "Gujarati": (0x0A80, 0x0AFF),
        "Tamil": (0x0B80, 0x0BFF),
        "Telugu": (0x0C00, 0x0C7F),
        "Kannada": (0x0C80, 0x0CFF),
        "Malayalam": (0x0D00, 0x0D7F),
    }

    # Phishing keywords in Indian languages (comprehensive)
    PHISHING_KEYWORDS = {
        "Hindi": [
            "बंद", "तुरंत", "ओटीपी", "खाता", "सत्यापन", "सत्यापित",
            "KYC", "आधार", "कार्ड", "विवरण", "यूपीआई", "ट्रांसफर",
            "क्रेडिट", "डेबिट", "पासवर्ड", "लॉगिन", "पुष्टि", "पहचान",
            "असामान्य", "गतिविधि", "निलंबित", "ब्लॉक", "रोक", "बंद",
            "समस्या", "त्रुटि", "विफल", "अनुमोदन", "जरूरत", "आवश्यक",
            "तुरंत कार्रवाই", "तुरंत सत्यापन", "तुरंत अपडेट", "तुरंत भेजें",
            "तुरंत दिखाएं", "तुरंत क्लिक", "तुरंत लॉगिन", "लाभ",
            "वॉलेट", "बैलेंस", "राशि", "भुगतान", "प्राप्त", "भेजें",
            "स्कैम", "धोखा", "जालसाजी", "संदेश", "लिंक", "क्लिक",
            "दबाएं", "यहां", "साइट", "वेबसाइट", "सर्वर", "सिस्टम",
            "अपडेट", "नवीनीकरण", "समाप्त", "एक्सपायर", "सत्र", "पैसे",
            "ब्याज", "लाभांश", "पुरस्कार", "जीत", "लॉटरी", "भाग्य",
            "बोनस", "ऑफर", "डिल", "छूट", "मुफ्त", "सीमित"
        ],
        "Tamil": [
            "தடை", "உடனே", "சரிபார்", "கணக்கு", "OTP", "ஆதார்",
            "கார்ட்", "விவரம்", "UPI", "பணம்", "மாற்றம்",
            "கடன்", "வரவு", "குறிப்பு", "கடவுச்சொல்", "உள்நுழைவு",
            "உறுதிப்படுத்த", "அடையாளம்", "அசாதாரண", "செயல்", "சுற்றப்பட",
            "தகராறு", "பிழை", "தோல்வி", "ஒப்புதல்", "தேவை",
            "அவசரம்", "உறுதிசெய்யவும்", "புதுப்பிக்கவும்", "அனுப்பவும்",
            "பூட்டு", "செயல்", "வாலட்", "கணக்கு", "சமநிலை",
            "பணம்", "வாங்க", "நகல்", "ஆர்", "வட்டி",
            "ஈவு", "பதக்கம்", "வெற்றி", "சூது", "சாதனை",
            "பணயம்", "சலுகை", "நிபந்தனை", "குறுக்கு", "குறையாக",
            "புதிய", "முடிவு", "டிராஃப்ட்", "உறுதி", "ரிசெட்"
        ],
        "Telugu": [
            "బ్లాక్", "వెంటనే", "OTP", "ధృవీకరించండి", "ఖాతా",
            "ఆధార్", "కార్డ్", "వివరాలు", "UPI", "పంపిన",
            "మార్పు", "తీసుకుని", "డెబిట్", "సంచిక", "మాటపదం",
            "ప్రవేశించండి", "నిర్ధారించండి", "గుర్తింపు", "అసాధారణ",
            "కార్యకలాపం", "నిలిపివేయబడినది", "సమస్య", "లోపం",
            "విఫలమైనది", "ఆమోదం", "అవసరం", "తక్షణ",
            "నవీకరించండి", "పంపండి", "లాక్", "చేయి",
            "వాలెట్", "సమనిలువ", "డబ్బు", "దేశం",
            "మూలం", "లాభం", "మార్పిడి", "మెచ్చుకోవటం",
            "నిర్ణయించుకొని", "ఆఫర్", "సమయపరిమితి", "ఇచ్చిపుచ్చు"
        ],
        "Bengali": [
            "বন্ধ", "তাৎক্ষণিক", "যাচাই", "কার্ড", "OTP",
            "আধার", "নম্বর", "বিবরণ", "UPI", "টাকা",
            "স্থানান্তর", "ক্রেডিট", "ডেবিট", "নোট", "পাসওয়ার্ড",
            "লগইন", "নিশ্চিত", "পরিচয়", "অস্বাভাবিক", "কার্যকলাপ",
            "স্থগিত", "সমস্যা", "ত্রুটি", "ব্যর্থ", "অনুমোদন",
            "প্রয়োজন", "জরুরি", "আপডেট", "পাঠান", "দেখান",
            "ক্লিক", "লিঙ্ক", "খোলা", "ওয়ালেট", "ভারসাম্য",
            "অর্থ", "পাওয়া", "পাঠান", "লটারি", "পুরস্কার",
            "জয়ী", "বোনাস", "মুক্ত", "অফার", "সীমিত"
        ],
        "Marathi": [
            "बंद", "तुरंत", "ओटीपी", "खाता", "सत्यापन",
            "आधार", "कार्ड", "विवरण", "यूपीआई", "पैसा",
            "स्थानांतरण", "क्रेडिट", "डेबिट", "नोट", "पासवर्ड",
            "लॉगिन", "पुष्टि", "पहचान", "असामान्य", "क्रिया",
            "स्थगित", "समस्या", "त्रुटि", "विफल", "मंजूरी",
            "आवश्यक", "जरूरी", "अपडेट", "पाठवा", "दाखव",
            "क्लिक", "लिंक", "उघड", "वॉलेट", "शिल्क",
            "रुपये", "संपत्ति", "विजय", "भाग्य", "पुरस्कार",
            "मुक्त", "ऑफर", "मर्यादित", "समयावधि", "सीमा"
        ],
        "Gujarati": [
            "બ્લોક", "તુરંત", "OTP", "ચકાસણી", "ખાતો",
            "આધાર", "કાર્ડ", "વિગતો", "UPI", "પૈસા",
            "સ્થાનાંતર", "ક્રેડિટ", "ડેબિટ", "નોંધ", "પાસવર્ડ",
            "લૉગઇન", "પુષ્ટિ", "ઓળખ", "અસામાન્ય", "કાર્યકલાપ",
            "સ્થગિત", "સમસ્યા", "ભૂલ", "નિષ્ફળ", "મંજૂરી",
            "જરૂરી", "કામજોરી", "અપડેટ", "મોકલો", "બતાવો",
            "ક્લિક", "લિંક", "ખોલો", "વૉલેટ", "સમતોલ",
            "નાણાં", "જીત", "ભાગ્ય", "પુરસ્કાર", "બોનસ",
            "મુક્ત", "ઓફર", "મર્યાદિત", "સમયઅવધિ", "સીમા"
        ],
    }

    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY")
        self.enabled = os.getenv("ENABLE_GROQ", "true").lower() == "true"
        self.api_url = "https://api.groq.com/openai/v1/chat/completions"
        self.model = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")

        # Load training examples
        self.examples = self._load_examples()

        if self.api_key and self.enabled:
            logger.info("Vernacular analyzer ready - Groq %s, %d examples loaded",
                       "enabled" if self.api_key else "disabled", len(self.examples))
        else:
            logger.warning("Vernacular analyzer in fallback mode (Groq disabled)")

    def _load_examples(self) -> List[Dict]:
        """Load phishing examples from vernacular dataset."""
        examples = []

        possible_paths = [
            "data/phishing_multilingual_vernacular_22lang.csv",
            "backend/data/phishing_multilingual_vernacular_22lang.csv",
            "../data/phishing_multilingual_vernacular_22lang.csv",
        ]

        csv_path = None
        for path in possible_paths:
            if os.path.exists(path):
                csv_path = path
                break

        if not csv_path:
            logger.warning("Vernacular dataset not found - using fallback only")
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

            logger.info("Loaded %d vernacular phishing examples", len(examples))
        except Exception as e:
            logger.error("Failed to load examples: %s", e)

        return examples

    def detect_language_script(self, text: str) -> str:
        """Detect which script/language the text uses."""
        if not text:
            return "unknown"

        for char in text:
            code = ord(char)
            for lang, (start, end) in self.SCRIPT_RANGES.items():
                if start <= code <= end:
                    return lang

        return "english"  # Default to English if no script match

    def normalize_text(self, text: str) -> str:
        """Normalize text for better matching."""
        # NFC normalization for Unicode combining characters
        return unicodedata.normalize('NFC', text)

    def extract_full_paragraph(self, text: str, keyword_pos: int, keyword_len: int,
                              lang: str) -> str:
        """Extract full paragraph/sentence containing the keyword."""
        # Sentence delimiters for different scripts
        delimiters = {
            "Hindi": ['।', '।', '.', '!', '?', '\n\n'],
            "Bengali": ['।', '.', '!', '?', '\n\n'],
            "Tamil": ['।', '.', '!', '?', '\n\n'],
            "Telugu": ['।', '.', '!', '?', '\n\n'],
            "Gujarati": ['।', '.', '!', '?', '\n\n'],
            "Marathi": ['।', '.', '!', '?', '\n\n'],
        }

        delims = delimiters.get(lang, ['।', '.', '!', '?', '\n\n'])

        # Find start of sentence
        start = keyword_pos
        for delim in delims:
            delim_pos = text.rfind(delim, 0, keyword_pos)
            if delim_pos != -1:
                start = min(start, delim_pos + len(delim))

        # Find end of sentence
        end = min(len(text), keyword_pos + keyword_len + 500)
        for delim in delims:
            delim_pos = text.find(delim, keyword_pos + keyword_len)
            if delim_pos != -1:
                end = delim_pos + len(delim)
                break

        paragraph = text[start:end].strip()

        # Minimum length for validity
        if len(paragraph) < 30:
            # If too short, expand slightly
            start = max(0, keyword_pos - 200)
            end = min(len(text), keyword_pos + keyword_len + 300)
            paragraph = text[start:end].strip()

        return paragraph

    def _build_groq_prompt(self) -> str:
        """Build Groq system prompt with diverse examples."""
        selected = []
        languages_seen = set()

        # Select diverse examples
        for ex in self.examples:
            lang = ex.get('language', 'Unknown')
            if lang not in languages_seen and len(selected) < 20:
                selected.append(ex)
                languages_seen.add(lang)

        prompt = """You are a VERNACULAR PHISHING EXPERT specializing in detecting phishing in Indian languages.
You have been trained on REAL phishing messages in Hindi, Tamil, Telugu, Bengali, Marathi, Gujarati, and other Indian languages.

CRITICAL INSTRUCTION: You MUST extract COMPLETE SENTENCES/PARAGRAPHS, not single words.
For pure vernacular text (100% Hindi/Tamil/Telugu/Bengali/Marathi/Gujarati), extract the ENTIRE suspicious message or full paragraph.

TRAINING EXAMPLES (All are phishing - label=1):
"""

        for i, ex in enumerate(selected, 1):
            prompt += f"\nExample {i} ({ex.get('language')} - {ex.get('category')}):\n"
            prompt += f'"{ex.get("text")}"\n'
            prompt += "Status: PHISHING - Risk 95-100\n"

        prompt += """
RULES FOR ANALYSIS:
1. CRITICAL: Extract COMPLETE SENTENCES/PARAGRAPHS (minimum 60 characters)
2. For pure vernacular text, extract the FULL paragraph or complete message
3. For URLs, include 150+ characters of surrounding context before and after
4. Assign risk 95-100 for messages similar to training examples
5. Look for these phishing tactics:
   - OTP/CVV/Card requests (ओटीपी/CVV मांगना, OTP/CVV கேட்டல்)
   - KYC/Verification threats (KYC की जांच, KYC சரிபார்ப்பு)
   - Account block/suspension threats (खाता बंद, கணக்கு தடை)
   - Urgent action demands (तुरंत, உடனே)
   - Fake links/URLs (संदिग्ध लिंक, சந்தேக சாரமான URL)
   - Impersonation (बैंक, सरकार की नकल, வங்கி/அரசு கூறிக்கொள்ளுதல்)

RESPONSE FORMAT (valid JSON only):
{
  "risk_score": 0-100,
  "is_phishing": true/false,
  "threats": [
    {
      "phrase": "COMPLETE SENTENCE/PARAGRAPH from message",
      "risk": 85-100,
      "category": "otp|kyc|account_threat|urgency|link|credential|impersonation",
      "explanation": "Why this is phishing (be specific)",
      "language": "Detected language"
    }
  ],
  "overall_assessment": "Summary of detected phishing tactics",
  "tactics": ["list", "of", "tactics"]
}

CRITICAL: If text is in pure vernacular (Hindi/Tamil/etc), extract FULL paragraphs, NOT single words."""

        return prompt

    async def translate_to_english(self, text: str) -> Optional[str]:
        """Translate vernacular text to English using Groq."""
        if not self.api_key or not self.enabled:
            return None

        # Detect if text contains vernacular scripts
        has_vernacular = False
        for char in text:
            code = ord(char)
            for lang, (start, end) in self.SCRIPT_RANGES.items():
                if start <= code <= end:
                    has_vernacular = True
                    break
            if has_vernacular:
                break

        # If no vernacular detected, return original text
        if not has_vernacular:
            logger.info("No vernacular script detected, skipping translation")
            return text

        try:
            logger.info("Translating vernacular text to English...")

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    self.api_url,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {
                                "role": "system",
                                "content": "You are a translation expert. Translate the given text from any Indian language (Hindi, Tamil, Telugu, Bengali, Marathi, Gujarati, etc.) to English. Preserve the exact meaning and structure. Only respond with the English translation, nothing else."
                            },
                            {
                                "role": "user",
                                "content": f"Translate this text to English:\n\n{text}"
                            }
                        ],
                        "temperature": 0.1,
                        "max_tokens": 3000,
                    },
                )

                if response.status_code != 200:
                    logger.error("Translation API error: %d", response.status_code)
                    return None

                data = response.json()
                translated = data["choices"][0]["message"]["content"].strip()

                logger.info("Translation successful: %d chars -> %d chars", len(text), len(translated))
                return translated

        except Exception as exc:
            logger.error("Translation failed: %s", exc)
            return None

    def _find_original_phrase(self, original_text: str, translated_phrase: str, translated_full_text: str) -> str:
        """Find the original vernacular phrase that corresponds to the translated phrase."""
        # Simple heuristic: find the position of the phrase in translated text,
        # then try to extract the corresponding segment from original text

        # Normalize for comparison
        translated_phrase_norm = translated_phrase.strip().lower()
        translated_full_norm = translated_full_text.strip().lower()

        # Find position in translated text
        pos = translated_full_norm.find(translated_phrase_norm)
        if pos == -1:
            # If not found, try fuzzy matching or return a segment from original
            # For now, return the first ~100 chars of original as fallback
            return original_text[:min(200, len(original_text))].strip()

        # Calculate approximate position ratio
        ratio_start = pos / len(translated_full_text) if len(translated_full_text) > 0 else 0
        ratio_end = (pos + len(translated_phrase)) / len(translated_full_text) if len(translated_full_text) > 0 else 0

        # Apply ratio to original text
        original_start = int(ratio_start * len(original_text))
        original_end = int(ratio_end * len(original_text))

        # Expand to word/sentence boundaries
        # Find sentence delimiters
        delimiters = ['।', '.', '!', '?', '\n']

        # Expand start to previous delimiter or start of text
        while original_start > 0 and original_text[original_start] not in delimiters:
            original_start -= 1
        if original_start > 0 and original_text[original_start] in delimiters:
            original_start += 1

        # Expand end to next delimiter or end of text
        while original_end < len(original_text) and original_text[original_end] not in delimiters:
            original_end += 1

        # Ensure we have at least 30 chars
        if original_end - original_start < 30:
            original_start = max(0, original_start - 50)
            original_end = min(len(original_text), original_end + 50)

        phrase = original_text[original_start:original_end].strip()

        # If still too short, return a larger segment
        if len(phrase) < 30:
            phrase = original_text[:min(200, len(original_text))].strip()

        return phrase

    async def analyze_with_groq(self, text: str) -> Optional[dict]:
        """Use Groq API with few-shot learning. First translates vernacular to English, then analyzes."""
        if not self.api_key or not self.enabled:
            return None

        try:
            # Store original text
            original_text = text

            # Step 1: Translate vernacular text to English
            translated_text = await self.translate_to_english(text)
            if translated_text is None:
                logger.warning("Translation failed, using original text")
                translated_text = text

            # Step 2: Analyze the translated (or original) text
            system_prompt = self._build_groq_prompt()

            async with httpx.AsyncClient(timeout=45.0) as client:
                response = await client.post(
                    self.api_url,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": f"Analyze this message for phishing:\n\n{translated_text}"}
                        ],
                        "temperature": 0.1,
                        "max_tokens": 2500,
                        "response_format": {"type": "json_object"},
                    },
                )

                if response.status_code != 200:
                    logger.error("Groq API error: %d", response.status_code)
                    return None

                data = response.json()
                content = data["choices"][0]["message"]["content"]
                result = json.loads(content)

                # Validate response
                if not isinstance(result.get("threats"), list):
                    result["threats"] = []
                if not isinstance(result.get("risk_score"), (int, float)):
                    result["risk_score"] = 0

                # Step 3: Map threats back to original vernacular text
                if translated_text != original_text:
                    logger.info("Mapping %d threats back to original vernacular text", len(result.get("threats", [])))
                    for threat in result.get("threats", []):
                        if "phrase" in threat:
                            # Find corresponding phrase in original text
                            original_phrase = self._find_original_phrase(
                                original_text,
                                threat["phrase"],
                                translated_text
                            )
                            threat["phrase"] = original_phrase
                            logger.debug("Mapped phrase: '%s' -> '%s'", threat["phrase"][:50], original_phrase[:50])

                logger.info("Groq analysis: %d threats, risk=%d",
                           len(result.get("threats", [])),
                           result.get("risk_score", 0))

                return result

        except Exception as exc:
            logger.error("Groq analysis failed: %s", exc)
            return None

    def _fallback_detection(self, text: str) -> dict:
        """Robust fallback for pure vernacular detection."""
        threats = []
        risk_score = 0

        text_normalized = self.normalize_text(text)

        # Detect what languages are present
        scripts_found = {}
        for char in text:
            code = ord(char)
            for lang, (start, end) in self.SCRIPT_RANGES.items():
                if start <= code <= end:
                    scripts_found[lang] = scripts_found.get(lang, 0) + 1

        primary_lang = max(scripts_found, key=scripts_found.get) if scripts_found else "english"

        logger.info("Detected languages: %s (primary: %s)", list(scripts_found.keys()), primary_lang)

        # Search for phishing keywords
        keywords_dict = self.PHISHING_KEYWORDS.get(primary_lang, [])

        for keyword in keywords_dict:
            # Find all occurrences
            pos = 0
            matches_found = 0
            while pos < len(text_normalized):
                idx = text_normalized.find(keyword, pos)
                if idx == -1:
                    break

                # Extract full paragraph containing keyword
                paragraph = self.extract_full_paragraph(text_normalized, idx, len(keyword), primary_lang)

                if len(paragraph) >= 30:
                    # Check if already in threats (avoid duplicates)
                    is_duplicate = any(t["phrase"] == paragraph for t in threats)
                    if not is_duplicate:
                        threats.append({
                            "phrase": paragraph,
                            "risk": 95,
                            "category": "vernacular_phishing",
                            "explanation": f"Pure {primary_lang} phishing detected - contains '{keyword}' with urgency/threat tactics",
                            "language": primary_lang
                        })
                        risk_score = 95
                        matches_found += 1

                    # Move past this keyword
                    pos = idx + len(keyword)
                else:
                    pos = idx + len(keyword)

                # Limit to 5 threats per language to avoid spam
                if matches_found >= 5:
                    break

        # Detect and extract URLs with context
        url_pattern = r'https?://[^\s]+'
        for match in re.finditer(url_pattern, text):
            url = match.group(0)
            start = max(0, match.start() - 150)
            end = min(len(text), match.end() + 100)
            context = text[start:end].strip()

            threats.append({
                "phrase": context,
                "risk": 90,
                "category": "suspicious_link",
                "explanation": f"Phishing URL detected in context - {url}",
                "language": primary_lang
            })
            risk_score = max(risk_score, 90)

        return {
            "risk_score": risk_score,
            "is_phishing": risk_score >= 50,
            "threats": threats[:10],  # Limit to 10 threats
            "overall_assessment": f"Detected {len(threats)} phishing indicators in {primary_lang}",
            "tactics": ["vernacular_phishing", "credential_request", "urgency", "account_threat"]
        }

    async def detect_threats(self, text: str) -> dict:
        """Main threat detection - Groq first, then fallback."""
        if not text or len(text.strip()) < 10:
            return {
                "risk_score": 0,
                "is_phishing": False,
                "threats": [],
                "overall_assessment": "Text too short",
                "tactics": [],
            }

        logger.info("Analyzing %d characters for vernacular phishing", len(text))

        # Try Groq first
        if self.api_key and self.enabled:
            result = await self.analyze_with_groq(text)
            if result:
                logger.info("Groq returned result with %d threats", len(result.get("threats", [])))
                return result
            logger.warning("Groq failed, falling back to pattern matching")

        # Fallback to pattern matching
        logger.info("Using vernacular pattern fallback")
        return self._fallback_detection(text)

    def is_available(self) -> bool:
        """Analyzer is always available (has fallback)."""
        return True


# Backward compatibility
GeminiAnalyzer = VernacularPhishingAnalyzer
FewShotAnalyzer = VernacularPhishingAnalyzer

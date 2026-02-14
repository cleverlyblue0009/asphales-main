"""Text cleaning, normalization, and language detection for code-mixed messages."""

import hashlib
import re
import unicodedata


# Devanagari Unicode range (Hindi, Sanskrit, Marathi, Nepali, Konkani)
_DEVANAGARI_RE = re.compile(r"[\u0900-\u097F]")
# Bengali
_BENGALI_RE = re.compile(r"[\u0980-\u09FF]")
# Tamil
_TAMIL_RE = re.compile(r"[\u0B80-\u0BFF]")
# Telugu
_TELUGU_RE = re.compile(r"[\u0C00-\u0C7F]")
# Kannada
_KANNADA_RE = re.compile(r"[\u0C80-\u0CFF]")
# Malayalam
_MALAYALAM_RE = re.compile(r"[\u0D00-\u0D7F]")
# Gujarati
_GUJARATI_RE = re.compile(r"[\u0A80-\u0AFF]")
# Punjabi (Gurmukhi)
_PUNJABI_RE = re.compile(r"[\u0A00-\u0A7F]")
# Odia
_ODIA_RE = re.compile(r"[\u0B00-\u0B7F]")
# Latin
_LATIN_RE = re.compile(r"[a-zA-Z]")
# Whitespace
_WHITESPACE_RE = re.compile(r"\s+")
_MAX_TEXT_LENGTH = 5000

# All vernacular script patterns
_VERNACULAR_PATTERNS = {
    "devanagari": _DEVANAGARI_RE,
    "bengali": _BENGALI_RE,
    "tamil": _TAMIL_RE,
    "telugu": _TELUGU_RE,
    "kannada": _KANNADA_RE,
    "malayalam": _MALAYALAM_RE,
    "gujarati": _GUJARATI_RE,
    "punjabi": _PUNJABI_RE,
    "odia": _ODIA_RE,
}


def normalize(text: str) -> str:
    """Lowercase, strip, collapse whitespace, and normalize Unicode."""
    text = unicodedata.normalize("NFC", text)
    text = text.strip().lower()
    text = _WHITESPACE_RE.sub(" ", text)
    return text


def clean(text: str) -> str:
    """Remove control characters but keep vernacular scripts and standard punctuation."""
    cleaned = []
    for ch in text:
        cat = unicodedata.category(ch)
        if cat.startswith("C") and ch not in ("\n", "\t"):
            continue
        cleaned.append(ch)
    return "".join(cleaned)


def detect_language(text: str) -> str:
    """Return detected language(s) based on script usage."""
    detected_scripts = []

    for script_name, pattern in _VERNACULAR_PATTERNS.items():
        if pattern.search(text):
            detected_scripts.append(script_name)

    has_latin = bool(_LATIN_RE.search(text))

    if detected_scripts and has_latin:
        return "multilingual"
    if detected_scripts:
        return detected_scripts[0]
    if has_latin:
        return "english"
    return "other"


def get_detected_scripts(text: str) -> list[str]:
    """Return list of all detected scripts in the text."""
    detected = []
    for script_name, pattern in _VERNACULAR_PATTERNS.items():
        if pattern.search(text):
            detected.append(script_name)
    if _LATIN_RE.search(text):
        detected.append("latin")
    return detected


def text_hash(text: str) -> str:
    """Generate a SHA-256 hex digest of the normalized text for cache keys."""
    normalized = normalize(text)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def validate_length(text: str) -> tuple[bool, str]:
    """Check that text is non-empty and within max length.

    Returns (is_valid, error_message).
    """
    if not text or not text.strip():
        return False, "Text is empty"
    if len(text) > _MAX_TEXT_LENGTH:
        return False, f"Text exceeds maximum length of {_MAX_TEXT_LENGTH} characters"
    return True, ""


def preprocess(text: str) -> str:
    """Full preprocessing pipeline: clean then normalize."""
    return normalize(clean(text))

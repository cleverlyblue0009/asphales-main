#!/usr/bin/env python
"""Train ML model on full multilingual dataset and test detection capabilities."""

import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.ml_classifier import MLPhishingClassifier
from utils.logger import setup_logger

logger = setup_logger("train_and_test")

# Test cases: (text, expected_label, language)
TEST_CASES = [
    # ===== PHISHING MESSAGES (label=1) =====
    ("Click here to verify your bank account immediately! Enter your OTP now!", 1, "English"),
    ("आपके खाते को ब्लॉक कर दिया गया है। तुरंत अपना पासवर्ड और OTP भेजें!", 1, "Hindi"),
    ("Your income tax refund is ready! Verify PAN and bank details asap", 1, "English"),
    ("Congratulations! You won 50 lakh rupees. Click here to claim your prize.", 1, "English"),
    ("పై ఖాతా నిలిపివేయబడింది. వెంటనే OTP పাঠండి.", 1, "Telugu"),
    ("உங்கள் UPI கணக்கு சரிபார்க்கவும். இப்போது OTP அனுப்பவும்.", 1, "Tamil"),
    ("क्रेडिट कार्ड जानकारी सत्यापित करें - अविलंब कार्रवाई आवश्यक", 1, "Hindi"),
    ("Your account will be suspended! Verify details now or face arrest.", 1, "English"),
    ("Processing fee required for loan approval. Transfer 5000 immediately.", 1, "English"),
    ("जीत गए 1 करोड़! अपनी जानकारी भेजें और पुरस्कार प्राप्त करें।", 1, "Hindi"),

    # ===== SAFE MESSAGES (label=0) =====
    ("Meeting scheduled for tomorrow at 2 PM in conference room", 0, "English"),
    ("कल की मीटिंग 2 बजे है। समय पर आएं।", 0, "Hindi"),
    ("Exam timetable announced on college portal, please check", 0, "English"),
    ("Class syllabus updated - check your email for details", 0, "English"),
    ("వచ్చే వారం సెమిస్టర్ పరీక్షలు ప్రారంభమవుతాయి.", 0, "Telugu"),
    ("Lunch break extended to 2 hours today", 0, "English"),
    ("புதிய ஆன்லைன் கোர్సு उपलब्ध हो गया है।", 0, "Tamil"),
    ("Weekend holiday declared for Independence Day", 0, "English"),
    ("नई लाइब्रेरी की सूचना प्रकाशित की गई है।", 0, "Hindi"),
    ("पाठ्यक्रम सामग्री अब डाउनलोड के लिए तैयार है।", 0, "Hindi"),
]


def main():
    logger.info("=" * 80)
    logger.info("TRAINING MODEL ON FULL MULTILINGUAL DATASET")
    logger.info("=" * 80)

    # Train the model
    classifier = MLPhishingClassifier()
    logger.info(f"Model: {classifier.model_name}")
    logger.info(f"Model info: {classifier.get_info()}")

    logger.info("\n" + "=" * 80)
    logger.info("TESTING MODEL ON DIVERSE MESSAGES")
    logger.info("=" * 80)

    correct = 0
    total = len(TEST_CASES)

    for text, expected_label, lang in TEST_CASES:
        result = classifier.predict(text)
        risk_score = result["risk_score"]
        is_phishing = result["is_phishing"]
        confidence = result["confidence"]

        # Determine if prediction is correct
        predicted_label = 1 if is_phishing else 0
        is_correct = predicted_label == expected_label
        correct += is_correct

        status = "✅ CORRECT" if is_correct else "❌ INCORRECT"
        expected_str = "PHISHING" if expected_label == 1 else "SAFE"
        predicted_str = "PHISHING" if is_phishing else "SAFE"

        logger.info(f"\n{status}")
        logger.info(f"Language: {lang}")
        logger.info(f"Text: {text[:70]}...")
        logger.info(f"Expected: {expected_str} | Predicted: {predicted_str}")
        logger.info(f"Risk Score: {risk_score}% | Confidence: {confidence:.3f}")

    logger.info("\n" + "=" * 80)
    logger.info(f"ACCURACY: {correct}/{total} = {(correct/total)*100:.1f}%")
    logger.info("=" * 80)

    # Test multilingual detection
    logger.info("\n" + "=" * 80)
    logger.info("MULTILINGUAL DETECTION TEST")
    logger.info("=" * 80)

    multilingual_tests = [
        "आपका खाता verify करें - Click here now!",
        "Please update your PAN - तुरंत भेजें",
        "Your refund is ready - अभी claim करें 1 crore rupees!",
    ]

    for text in multilingual_tests:
        result = classifier.predict(text)
        logger.info(
            f"\nText: {text}\nRisk: {result['risk_score']}% | "
            f"Phishing: {result['is_phishing']} | Confidence: {result['confidence']:.3f}"
        )

    logger.info("\n" + "=" * 80)
    logger.info("✅ TRAINING AND TESTING COMPLETE")
    logger.info("=" * 80)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Test script for vernacular phishing detection.
Tests pure Hindi, Tamil, Telugu, Bengali, Marathi, Gujarati messages.
"""

import asyncio
import json
import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.vernacular_analyzer import VernacularPhishingAnalyzer


async def test_analyzer():
    """Test vernacular analyzer with sample messages."""

    analyzer = VernacularPhishingAnalyzer()

    # Test cases: pure vernacular phishing messages
    test_messages = {
        "Pure Hindi": {
            "text": "तुरंत ध्यान दें! आपके खाते को असामान्य गतिविधि के कारण अस्थायी रूप से निलंबित कर दिया गया है। कृपया तुरंत अपनी पहचान सत्यापित करें अन्यथा आपका खाता स्थायी रूप से बंद हो जाएगा। यहाँ सत्यापित करें: https://sbi-verify.tk/login",
            "expected_risk": 90,
            "language": "Hindi"
        },
        "Pure Tamil": {
            "text": "மைஷர்: ஆபத்து! உங்கள் கணக்கு கூட்ட விளக்கங்கள் நீக்கப்பட்டுள்ளது. உடனே உங்கள் விவரங்கள் புதுப்பிக்கவும் வேண்டுமென்றால் கணக்கு நிரந்தரமாக மூடப்பட்டுவிடும்.",
            "expected_risk": 85,
            "language": "Tamil"
        },
        "Pure Telugu": {
            "text": "ఆపరేటర్: ఎరిగి! మీ ఖాతా సమస్్, ఖాతా నిలుపుట్‌ చేయబడింది. వెంటనే సరిచేయండి అది దీర్ఘకాలంగా నిలుపుట్‌ చేయబడుతుంది.",
            "expected_risk": 80,
            "language": "Telugu"
        },
        "Pure Bengali": {
            "text": "আপনার ব্যাংক অ্যাকাউন্ট অনুমোদিত হয়নি। এখনই যাচাই করুন এবং ক্রেডিট কার্ড নম্বর পাঠান। তাৎক্ষণিক পুনরায় সক্রিয় করুন।",
            "expected_risk": 85,
            "language": "Bengali"
        },
        "Pure Marathi": {
            "text": "आपल्या खातेवर जलद दिवस नष्ट होहैं। तुरंत सत्यापन करो आधार आणि कार्ड विवरण पाठवा।",
            "expected_risk": 85,
            "language": "Marathi"
        },
        "Pure Gujarati": {
            "text": "તમારો બેંક ખાતો ફ્લોક કરવામાં આવ્યો છે. તુરંત ચકાસણી કરો અને ક્રેડિટ કાર્ડ વિગતો મોકલો.",
            "expected_risk": 85,
            "language": "Gujarati"
        },
        "Hinglish Mixed": {
            "text": "तुरंत verify करो! Aapka account suspicious activity के कारण block हो सकता है। अभी ही अपने card details भेजो: https://fake-bank.com/verify",
            "expected_risk": 80,
            "language": "Hinglish"
        },
        "Safe Hindi Message": {
            "text": "कल सुबह 9 बजे मीटिंग है। कृपया समय पर आएं।",
            "expected_risk": 0,
            "language": "Hindi"
        },
        "Hindi with URL": {
            "text": "आपकी KYC सत्यापन विफल हुई। तुरंत आधार और पैन भेजें। यहां लॉगिन करें: https://malicious-kyc.verify/aadhar",
            "expected_risk": 90,
            "language": "Hindi"
        },
    }

    print("=" * 80)
    print("VERNACULAR PHISHING DETECTION TEST SUITE")
    print("=" * 80)
    print(f"✅ Analyzer initialized (Groq {'enabled' if analyzer.api_key else 'disabled'})")
    print(f"✅ Loaded {len(analyzer.examples)} training examples")
    print("=" * 80)

    results = {
        "passed": 0,
        "failed": 0,
        "details": []
    }

    for test_name, test_data in test_messages.items():
        print(f"\n🧪 TEST: {test_name}")
        print(f"   Language: {test_data['language']}")
        print(f"   Text: {test_data['text'][:100]}...")
        print(f"   Expected Risk: {test_data['expected_risk']}")

        try:
            # Analyze
            result = await analyzer.detect_threats(test_data['text'])

            risk_score = result.get('risk_score', 0)
            is_phishing = result.get('is_phishing', False)
            threats = result.get('threats', [])

            print(f"   ✅ Analysis complete")
            print(f"      Risk Score: {risk_score}")
            print(f"      Is Phishing: {is_phishing}")
            print(f"      Threats Found: {len(threats)}")

            # Show detected threats
            if threats:
                for i, threat in enumerate(threats[:3], 1):
                    phrase = threat.get('phrase', '')[:80]
                    category = threat.get('category', '')
                    explanation = threat.get('explanation', '')[:80]
                    print(f"      Threat {i}: [{category}] Risk={threat.get('risk')}%")
                    print(f"                Phrase: {phrase}...")
                    print(f"                Explain: {explanation}...")

            # Check if result is reasonable
            expected_risk = test_data['expected_risk']
            test_passed = False

            if expected_risk == 0:
                # Safe message - should have low risk
                test_passed = risk_score < 40
            else:
                # Phishing message - should have high risk
                test_passed = risk_score >= 70 and len(threats) > 0

            if test_passed:
                print(f"   ✅ PASSED")
                results['passed'] += 1
            else:
                print(f"   ❌ FAILED (Expected risk ~{expected_risk}, got {risk_score})")
                results['failed'] += 1

            results['details'].append({
                "test": test_name,
                "passed": test_passed,
                "risk_score": risk_score,
                "threats_found": len(threats),
                "expected_risk": expected_risk
            })

        except Exception as e:
            print(f"   ❌ ERROR: {e}")
            results['failed'] += 1
            results['details'].append({
                "test": test_name,
                "passed": False,
                "error": str(e)
            })

    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"✅ Passed: {results['passed']}")
    print(f"❌ Failed: {results['failed']}")
    print(f"📊 Success Rate: {results['passed']}/{results['passed'] + results['failed']} ({100*results['passed']/(results['passed'] + results['failed']):.1f}%)")
    print("=" * 80)

    # Detailed results
    print("\nDETAILED RESULTS:")
    for detail in results['details']:
        status = "✅" if detail.get('passed') else "❌"
        test_name = detail.get('test', 'Unknown')
        risk = detail.get('risk_score', 'N/A')
        threats = detail.get('threats_found', 'N/A')
        print(f"{status} {test_name:30} Risk={risk:3} Threats={threats}")

    return results['failed'] == 0


if __name__ == "__main__":
    print("Starting vernacular phishing detection tests...\n")

    success = asyncio.run(test_analyzer())

    sys.exit(0 if success else 1)

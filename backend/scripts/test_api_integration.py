#!/usr/bin/env python3
"""
Test the full API integration with FastAPI backend.
"""

import asyncio
import json
import httpx
import time
from typing import Optional

BASE_URL = "http://localhost:8000"


async def test_api():
    """Test API endpoints."""

    test_cases = [
        {
            "name": "Pure Hindi Phishing",
            "text": "तुरंत ध्यान दें! आपके खाते को असामान्य गतिविधि के कारण अस्थायी रूप से निलंबित कर दिया गया है। कृपया तुरंत अपनी पहचान सत्यापित करें।",
            "expect_phishing": True
        },
        {
            "name": "Pure Tamil Phishing",
            "text": "மைஷர்: ஆபத்து! உங்கள் கணக்கு கூட்ட விளக்கங்கள் நீக்கப்பட்டுள்ளது. உடனே உங்கள் விவரங்கள் புதுப்பிக்கவும்.",
            "expect_phishing": True
        },
        {
            "name": "Safe Message",
            "text": "कल सुबह 9 बजे मीटिंग है।",
            "expect_phishing": False
        }
    ]

    print("=" * 80)
    print("API INTEGRATION TEST")
    print("=" * 80)

    # Check if server is running
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{BASE_URL}/", timeout=2.0)
            if response.status_code == 200:
                print("✅ Backend API is running")
            else:
                print(f"❌ Backend returned {response.status_code}")
                return False
    except Exception as e:
        print(f"❌ Cannot connect to backend: {e}")
        print(f"   Make sure backend is running at {BASE_URL}")
        print(f"   Run: cd backend && python -m uvicorn app:app --reload")
        return False

    print("=" * 80)

    results = {"passed": 0, "failed": 0}

    async with httpx.AsyncClient(timeout=30.0) as client:
        for test in test_cases:
            print(f"\n🧪 Test: {test['name']}")
            print(f"   Text: {test['text'][:80]}...")

            try:
                start = time.time()
                response = await client.post(
                    f"{BASE_URL}/analyze",
                    json={"text": test['text']}
                )
                elapsed = time.time() - start

                if response.status_code != 200:
                    print(f"   ❌ API returned {response.status_code}")
                    results['failed'] += 1
                    continue

                result = response.json()

                # Extract data
                risk_score = result.get('overall_risk', 0)
                severity = result.get('severity', 'low')
                threats = result.get('threats', [])
                method = result.get('method', 'unknown')

                print(f"   ✅ Response received in {elapsed:.2f}s")
                print(f"      Risk Score: {risk_score}/100")
                print(f"      Severity: {severity}")
                print(f"      Method: {method}")
                print(f"      Threats: {len(threats)}")

                # Show threats
                for i, threat in enumerate(threats[:2], 1):
                    phrase = threat.get('phrase', '')[:60]
                    category = threat.get('category', '')
                    print(f"      - [{category}] {phrase}...")

                # Check if result matches expectation
                expect_phishing = test['expect_phishing']
                is_phishing = risk_score > 70
                passed = is_phishing == expect_phishing

                if passed:
                    print(f"   ✅ PASSED")
                    results['passed'] += 1
                else:
                    print(f"   ❌ FAILED (expected {'phishing' if expect_phishing else 'safe'}, got risk={risk_score})")
                    results['failed'] += 1

            except Exception as e:
                print(f"   ❌ ERROR: {e}")
                results['failed'] += 1

    print("\n" + "=" * 80)
    print(f"✅ Passed: {results['passed']}/{len(test_cases)}")
    print(f"❌ Failed: {results['failed']}/{len(test_cases)}")
    print("=" * 80)

    return results['failed'] == 0


if __name__ == "__main__":
    success = asyncio.run(test_api())
    exit(0 if success else 1)

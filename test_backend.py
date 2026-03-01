import sys
import os

# Add backend directory to sys.path so we can import from it
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

import asyncio
from backend.main import analyze, AnalyzeRequest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def run_test():
    test_text_phishing = "URGENT: Your account will be suspended in 24 hours. Click here to verify your details: http://suspicious-link.net/login"
    test_text_safe = "Hi team, Just wanted to check in on the progress of the Q3 roadmap. Let's catch up tomorrow at 10 AM. Thanks, John"

    print("--- Testing Phishing Email ---")
    response_phish = client.post("/analyze", json={"content": test_text_phishing})
    print(f"Status Code: {response_phish.status_code}")
    if response_phish.status_code == 200:
        data = response_phish.json()
        print(f"Final Score: {data.get('final_score')}")
        print(f"Risk Level: {data.get('risk_level')}")
        print(f"AI Score: {data.get('ai_score')}")
        print(f"Heuristic Score: {data.get('heuristic_score')}")
        print(f"Summary: {data.get('summary')}")
    else:
        print(response_phish.text)

    print("\n--- Testing Safe Email ---")
    response_safe = client.post("/analyze", json={"content": test_text_safe})
    print(f"Status Code: {response_safe.status_code}")
    if response_safe.status_code == 200:
        data = response_safe.json()
        print(f"Final Score: {data.get('final_score')}")
        print(f"Risk Level: {data.get('risk_level')}")
        print(f"AI Score: {data.get('ai_score')}")
        print(f"Heuristic Score: {data.get('heuristic_score')}")
    else:
        print(response_safe.text)

if __name__ == "__main__":
    run_test()

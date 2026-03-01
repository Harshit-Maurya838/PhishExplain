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
    # A clearly malicious email meant to trigger High Risk heuristic combinations
    phishing_email = "URGENT ACTION REQUIRED: Your account will be locked immediately due to unauthorized access! Login to continue and confirm your password to prevent deletion. http://192.168.1.1/login.xyz"

    # A safe email
    safe_email = "Hey team, just wanted to check if we are still on for the 3pm meeting. Let me know if you need to reschedule."

    print("--- Testing Phishing Email ---")
    response_phish = client.post("/analyze", json={"content": phishing_email})
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
    response_safe = client.post("/analyze", json={"content": safe_email})
    print(f"Status Code: {response_safe.status_code}")
    if response_safe.status_code == 200:
        data = response_safe.json()
        print(f"Final Score: {data.get('final_score')}")
        print(f"Risk Level: {data.get('risk_level')}")
        print(f"AI Score: {data.get('ai_score')}")
        print(f"Heuristic Score: {data.get('heuristic_score')}")
    else:
        print(f"Error: {response_safe.text}")

if __name__ == "__main__":
    run_test()

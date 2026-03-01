# PhishExplain 🔐

PhishExplain is a privacy-first, hybrid AI phishing detection system that not only detects suspicious emails or webpages but also explains *why* they are risky.

Unlike traditional spam filters that silently block content, PhishExplain turns every phishing attempt into a learning opportunity by highlighting manipulation tactics and providing human-readable explanations.

---

## 🚀 Core Idea

PhishExplain combines:

* 🧠 Lightweight Transformer-based AI model (local inference)
* 🛠 Heuristic rule-based detection engine
* 📊 Hybrid scoring system
* 📘 Explainable threat summaries
* 🌐 Chrome Extension for real-time webpage analysis

All processing runs locally on the user’s machine.
No data is sent to external servers.

---

## 🏗 Architecture Overview

Hybrid Detection Pipeline:

User Input (Email/Webpage Text)
↓
Feature Extraction Engine
↓
Heuristic Rule Engine
↓
Local AI Classifier (Transformer Model)
↓
Hybrid Risk Scoring
↓
Threat Summary + Highlighted Output

---

## 🧠 Hybrid Detection Logic

### 1️⃣ Heuristic Detection

Detects:

* Urgency language
* Fear tactics
* Credential harvesting attempts
* Institutional impersonation
* Portal/login pretexts
* Suspicious URL patterns
* Domain structure anomalies

Each rule contributes weighted risk points.

### 2️⃣ AI Semantic Classification

A lightweight transformer model analyzes contextual phishing patterns.

Outputs:

* AI Score (0–100)
* Confidence
* Predicted label (phishing/safe)

### 3️⃣ Hybrid Risk Score

Final Score = Weighted combination of:

* AI Score
* Heuristic Score

Dynamic weighting ensures:

* Obvious phishing → HIGH
* Subtle phishing → MEDIUM
* Legitimate emails → LOW

---

## 📊 Risk Levels

| Score Range | Risk Level |
| ----------- | ---------- |
| 0–29        | Low        |
| 30–59       | Medium     |
| 60–100      | High       |

---

## 🌐 Chrome Extension

The Chrome Extension allows:

* One-click analysis of current webpage
* Extracts visible page text
* Sends to local backend
* Displays:

  * Final Risk Score
  * Risk Level
  * AI Score
  * Heuristic Score
  * Threat Summary

All analysis runs locally via:

[http://127.0.0.1:8000/analyze](http://127.0.0.1:8000/analyze)

---

## 🛠 Tech Stack

Backend:

* Python
* FastAPI
* HuggingFace Transformers
* PyTorch (CPU inference)

Frontend:

* Basic HTML + CSS
* Chrome Extension (Manifest V3)

Model:

* Lightweight phishing classification transformer (CPU-friendly)

---

## ⚙️ How to Run

### 1️⃣ Start Backend

```bash
uvicorn main:app --reload
```

Backend runs at:
[http://127.0.0.1:8000](http://127.0.0.1:8000)

### 2️⃣ Load Chrome Extension

1. Open Chrome
2. Go to chrome://extensions
3. Enable Developer Mode
4. Click "Load Unpacked"
5. Select extension folder

### 3️⃣ Test

* Open any webpage (e.g., email client)
* Click PhishExplain extension
* Click "Analyze Current Page"

---

## 🔍 Example Capabilities

Detects:

* Fake banking emails
* IT password reset scams
* Payroll phishing
* Internship portal scams
* Fake document share links

Provides:

* Risk breakdown
* Highlighted suspicious phrases
* Explanation of psychological manipulation
* Verification guidance

---

## 🛡 Privacy-First Design

* No cloud API usage
* No external data transmission
* Fully local inference
* Suitable for sensitive enterprise environments

---

## 🎯 Future Improvements

* ONNX optimization for faster inference
* Domain reputation checking
* Continual learning from user feedback
* Inline Gmail DOM highlighting
* Mobile email client integration

---

## 📌 Project Vision

PhishExplain is designed not just to block phishing but to educate users.

Instead of blind trust in security software, users understand:

* How phishing works
* What manipulation tactics look like
* How to verify suspicious messages safely

---

PhishExplain demonstrates how modern phishing detection can be both intelligent and educational.

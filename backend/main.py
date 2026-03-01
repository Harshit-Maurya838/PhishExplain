from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Dict, Any
import os
import logging
import time

from analyzer import FeatureExtractor, RuleEngine, RiskScorer, Explainer, Highlighter, ThreatSummaryGenerator, AIClassifier

# Configure structured routing logger
logger = logging.getLogger("PhishExplain.API")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

app = FastAPI(title="PhishExplain API")

# Mount frontend directory for static files
frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
app.mount("/static", StaticFiles(directory=frontend_path), name="static")

# Initialize Analyzer Components
extractor = FeatureExtractor()
rule_engine = RuleEngine()
explainer = Explainer()
highlighter = Highlighter()
threat_generator = ThreatSummaryGenerator()
ai_classifier = AIClassifier()
# In a real app the RiskScorer would need to map the risk categories 
# But for now we just use a basic thresholding as requested.
# I'll add a helper function instead of a heavy class for the final scoring

# Feature type sets used by scoring helpers
_LINK_TYPES = {
    "URL", "Insecure Link (HTTP)", "Suspicious URL (IP Based)",
    "Suspicious URL (TLD)", "Suspicious URL Keyword", "Shortened Link",
    "Fake Subdomain Impersonation", "Homograph Attack (Punycode/Cyrillic)",
    "Suspicious Domain Keyword", "Multi-Hyphen Domain", "Long Domain"
}
_CREDENTIAL_TYPES = {"Credential Request", "Portal Context", "Institutional Impersonation"}
_ROLE_TYPES = {"Institutional Impersonation", "Authority Impersonation"}
_IMPERSONATION_TYPES = {"Institutional Impersonation", "Authority Impersonation"}
_PORTAL_TYPES = {"Portal Context", "Credential Request"}
_PRETEXT_TYPES = {"Business Pretext", "Financial Bait"}
_PSYCH_TYPES = {"Contextual Urgency", "Generic Urgency", "Fear Tactics", "Scarcity Manipulation"}
_URL_STRUCTURAL_TYPES = {
    "Insecure Link (HTTP)", "Suspicious URL (IP Based)", "Suspicious URL (TLD)",
    "Suspicious URL Keyword", "Shortened Link", "Fake Subdomain Impersonation",
    "Homograph Attack (Punycode/Cyrillic)", "Suspicious Domain Keyword",
    "Multi-Hyphen Domain", "Long Domain"
}


def _boost_ai_score(ai_result: dict, features: List[Dict[str, Any]]) -> float:
    """
    Applies a +15 contextual boost to the AI score when the AI predicts SAFE
    but strong phishing context signals (portal/credential + link) are present.
    Returns the (potentially boosted) ai_score, capped at 100.
    """
    ai_score = ai_result.get("ai_score", 0.0)
    if ai_result.get("label") != "safe":
        return ai_score   # Only boost when AI says safe to avoid over-inflation

    feature_types = {f.get("type", "") for f in features}
    has_link = bool(_LINK_TYPES & feature_types)

    if not has_link:
        return ai_score   # No link → no boost

    boost_triggers = [
        bool({"Portal Context", "Credential Request"} & feature_types),         # login/confirm + link
        "Business Pretext" in feature_types,                                      # payroll / doc shared + link
        any("banking" in f.get("matched_text", "").lower() for f in features),   # banking keyword
    ]

    if any(boost_triggers):
        ai_score = min(ai_score + 15, 100)
        logger.info(f"Contextual AI boost applied. New ai_score: {ai_score:.2f}")

    return ai_score


def calculate_risk(features: List[Dict[str, Any]], ai_result: dict) -> Dict[str, Any]:
    # Raw heuristic sum (capped at 100)
    heuristic_score = min(sum(f.get("score", 0) for f in features), 100)

    # Contextual AI boost (before hybrid calculation)
    ai_score = _boost_ai_score(ai_result, features)

    # --- Dynamic hybrid weighting ---
    if heuristic_score > 50:
        ai_weight, heuristic_weight = 0.6, 0.4
    else:
        ai_weight, heuristic_weight = 0.7, 0.3

    final_score = (ai_weight * ai_score) + (heuristic_weight * heuristic_score)
    final_score = max(0.0, min(final_score, 100.0))

    # Base risk level from final score
    if final_score <= 29:
        level = "Low"
    elif final_score <= 59:
        level = "Medium"
    else:
        level = "High"

    # --- Override 1: Force HIGH when both signals are strongly phishing ---
    if ai_score > 85 and heuristic_score > 40:
        level = "High"
        logger.info("Override: AI > 85 & Heuristic > 40 → forced HIGH")

    # --- Override 2: Minimum MEDIUM when heuristics dominate a weak AI ---
    if ai_score < 40 and heuristic_score > 60 and level == "Low":
        level = "Medium"
        logger.info("Override: AI < 40 & Heuristic > 60 → minimum MEDIUM")

    # --- False Positive Safeguard ---
    # If there are no links, no credential signals, and no impersonation, clamp to LOW
    feature_types = {f.get("type", "") for f in features}
    has_links       = bool(_LINK_TYPES & feature_types)
    has_credentials = bool(_CREDENTIAL_TYPES & feature_types)
    has_impersonation = bool(_ROLE_TYPES & feature_types)

    if not has_links and not has_credentials and not has_impersonation:
        if level != "Low":
            level = "Low"
            logger.info("FP Safeguard: No links, credentials, or impersonation — clamped to LOW")

    # --- Heuristic Breakdown by Category ---
    impersonation_score = sum(
        f.get("score", 0) for f in features if f["type"] in _IMPERSONATION_TYPES
    )
    portal_score = sum(
        f.get("score", 0) for f in features if f["type"] in _PORTAL_TYPES
    )
    url_structure_score = sum(
        f.get("score", 0) for f in features if f["type"] in _URL_STRUCTURAL_TYPES
    )
    pretext_score = sum(
        f.get("score", 0) for f in features if f["type"] in _PRETEXT_TYPES
    )
    psych_score = sum(
        f.get("score", 0) for f in features if f["type"] in _PSYCH_TYPES
    )

    return {
        "final_score": round(final_score, 2),
        "risk_level": level,
        "heuristic_score": heuristic_score,
        "ai_score": round(ai_score, 2),
        "score_breakdown": {
            "ai_weight": ai_weight,
            "heuristic_weight": heuristic_weight
        },
        "heuristic_breakdown": {
            "impersonation": impersonation_score,
            "portal_context": portal_score,
            "url_structure": url_structure_score,
            "business_pretext": pretext_score,
            "psychological_tactics": psych_score
        }
    }

class AnalyzeRequest(BaseModel):
    content: str


@app.get("/")
async def root():
    # Serve index.html
    index_path = os.path.join(frontend_path, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return {"message": "Frontend not found"}

@app.post("/analyze")
async def analyze(request: AnalyzeRequest):
    text = request.content
    logger.info("Received analyze request. Starting pipeline.")
    
    # 1. Feature Extraction Layer
    features = extractor.extract_features(text)
    
    # 2. Risk Classification Engine (Rules + Confidence)
    scored_features = rule_engine.evaluate(features)
    logger.info(f"Engine evaluated {len(scored_features)} scored/confident features.")
    
    # 3. Explanation Engine (Multidimensional)
    explained_features = explainer.explain(scored_features)
    
    # 4. AI Classification
    logger.info("Running AI Classification.")
    start_time = time.time()
    ai_result = ai_classifier.analyze(text)
    inference_time = round((time.time() - start_time) * 1000, 2)
    logger.info(f"AI Inference Time: {inference_time}ms")
    
    # 5. Risk Scoring System (Hybrid)
    risk_data = calculate_risk(explained_features, ai_result)
    logger.info(f"Final Risk Calculated: Final: {risk_data['final_score']}, Heuristic: {risk_data['heuristic_score']}, AI: {risk_data['ai_score']}")
    
    # 6. Threat Summary Generation
    threat_summary = threat_generator.generate(
        risk_data["risk_level"], 
        explained_features, 
        ai_result.get("explanation", "")
    )
    logger.info("Generated contextual threat summary.")
    
    # 7. Highlighting Engine
    # AI only generated string summaries, the `explained_features` array only contains heuristic rule triggers!
    # Therefore, AI token hallucination is structurally impossible in the HTML highlighting.
    highlighted_html = highlighter.highlight(text, explained_features)
    
    logger.info("Pipeline complete. Returning response payload.")
    return JSONResponse(content={
        "final_score": risk_data["final_score"],
        "risk_level": risk_data["risk_level"],
        "ai_score": risk_data["ai_score"],
        "heuristic_score": risk_data["heuristic_score"],
        "score_breakdown": risk_data["score_breakdown"],
        "heuristic_breakdown": risk_data["heuristic_breakdown"],
        "summary": threat_summary,
        "flags": explained_features,
        "highlighted_html": highlighted_html
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

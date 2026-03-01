from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Dict, Any
import os
import logging

from analyzer import FeatureExtractor, RuleEngine, RiskScorer, Explainer, Highlighter, ThreatSummaryGenerator

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
# In a real app the RiskScorer would need to map the risk categories 
# But for now we just use a basic thresholding as requested.
# I'll add a helper function instead of a heavy class for the final scoring
def calculate_risk(features: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_score = sum([f.get("score", 0) for f in features])
    final_score = min(total_score, 100)
    
    if final_score <= 30:
        level = "Low"
    elif final_score <= 70:
        level = "Medium"
    else:
        level = "High"
        
    return {
        "risk_score": final_score,
        "risk_level": level
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
    
    # 4. Risk Scoring System
    risk_data = calculate_risk(explained_features)
    logger.info(f"Final Risk Calculated: {risk_data['risk_score']} ({risk_data['risk_level']})")
    
    # 5. Threat Summary Generation
    threat_summary = threat_generator.generate(risk_data["risk_level"], explained_features)
    logger.info("Generated contextual threat summary.")
    
    # 6. Highlighting Engine
    highlighted_html = highlighter.highlight(text, explained_features)
    
    logger.info("Pipeline complete. Returning response payload.")
    return JSONResponse(content={
        "risk_score": risk_data["risk_score"],
        "risk_level": risk_data["risk_level"],
        "threat_summary": threat_summary,
        "flags": explained_features,
        "highlighted_html": highlighted_html
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

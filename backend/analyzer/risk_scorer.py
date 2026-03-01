from typing import List, Dict, Any

class RiskScorer:
    def __init__(self):
        self.max_score = 100

    def score(self, evaluated_features: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Takes features with scores and calculates the overall risk.
        Returns the overall score and risk level.
        """
        total_score = sum([f.get("score", 0) for f in evaluated_features])
        
        # Cap score at 100
        final_score = min(total_score, self.max_score)
        
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

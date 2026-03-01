from typing import List, Dict, Any

class RuleEngine:
    def __init__(self):
        # Define baseline weights and dynamic confidences for different feature types
        self.rules = {
            "Contextual Urgency": {"score": 15, "confidence": 0.95},
            "Generic Urgency": {"score": 15, "confidence": 0.50},
            
            "Fear Tactics": {"score": 20, "confidence": 0.85},
            "Authority Impersonation": {"score": 40, "confidence": 0.80},
            "Scarcity Manipulation": {"score": 25, "confidence": 0.75},
            
            "Credential Request": {"score": 25, "confidence": 0.90},
            "Financial Bait": {"score": 35, "confidence": 0.80},
            
            "Insecure Link (HTTP)": {"score": 30, "confidence": 0.95},
            "Suspicious URL (IP Based)": {"score": 30, "confidence": 0.98},
            "Suspicious URL (TLD)": {"score": 30, "confidence": 0.70},
            "Suspicious URL Keyword": {"score": 30, "confidence": 0.85},
            "Shortened Link": {"score": 20, "confidence": 0.60},
            "Fake Subdomain Impersonation": {"score": 45, "confidence": 0.95},
            "Homograph Attack (Punycode/Cyrillic)": {"score": 55, "confidence": 0.85},
            "URL": {"score": 0, "confidence": 0.10} # Base URL has no inherent risk
        }

    def evaluate(self, features: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Takes generic extracted features and maps them to a weighted risk score and confidence level.
        Returns the features enriched with 'score' and 'confidence'.
        """
        evaluated_features = []
        
        # We need to track the string positions.
        # If we matched "Contextual Urgency" at offsets 5-20, we should ignore "Generic Urgency" 
        # matches that fall within those same boundaries to avoid double counting.
        contextual_intervals = []
        for feature in features:
            if feature["type"] == "Contextual Urgency":
                 contextual_intervals.append((feature["start"], feature["end"]))

        seen_matches = set()
        
        for feature in features:
            feat_type = feature["type"]
            start = feature["start"]
            end = feature["end"]
            
            # Skip Generic Urgency if it overlaps with a Contextual Urgency match
            if feat_type == "Generic Urgency":
                 overlap = any(
                     (start >= ctx_start and start < ctx_end) or 
                     (end > ctx_start and end <= ctx_end)
                     for ctx_start, ctx_end in contextual_intervals
                 )
                 if overlap:
                     continue

            # Exact string deduping
            match_key = f"{feat_type}:{start}:{end}"
            if match_key in seen_matches:
                continue
            seen_matches.add(match_key)
            
            rule = self.rules.get(feat_type, {"score": 0, "confidence": 0.0})
            
            evaluated_feature = feature.copy()
            evaluated_feature["score"] = rule["score"]
            evaluated_feature["confidence"] = rule["confidence"]
            
            # Don't return zero score items unless they are URLs mapped for context
            if rule["score"] > 0 or feat_type == "URL":
                 evaluated_features.append(evaluated_feature)
            
        return evaluated_features

from typing import List, Dict, Any

class RuleEngine:
    def __init__(self):
        # Define baseline weights and dynamic confidences for different feature types
        self.rules = {
            # ── Urgency ──
            "Contextual Urgency": {"score": 15, "confidence": 0.95},
            "Generic Urgency": {"score": 15, "confidence": 0.50},

            # ── Psychological / Social Engineering ──
            "Fear Tactics": {"score": 20, "confidence": 0.85},
            "Authority Impersonation": {"score": 40, "confidence": 0.80},
            "Scarcity Manipulation": {"score": 25, "confidence": 0.75},

            # ── Credential & Financial ──
            "Credential Request": {"score": 25, "confidence": 0.90},
            "Financial Bait": {"score": 35, "confidence": 0.80},

            # ── Institutional / Contextual Composite ──
            "Institutional Impersonation": {"score": 20, "confidence": 0.80},
            "Portal Context": {"score": 25, "confidence": 0.85},
            "Business Pretext": {"score": 20, "confidence": 0.75},

            # ── URL Intelligence (primary) ──
            "Insecure Link (HTTP)": {"score": 20, "confidence": 0.95},
            "Suspicious URL (IP Based)": {"score": 30, "confidence": 0.98},
            "Suspicious URL (TLD)": {"score": 30, "confidence": 0.70},
            "Suspicious URL Keyword": {"score": 30, "confidence": 0.85},
            "Shortened Link": {"score": 20, "confidence": 0.60},
            "Fake Subdomain Impersonation": {"score": 45, "confidence": 0.95},
            "Homograph Attack (Punycode/Cyrillic)": {"score": 55, "confidence": 0.85},

            # ── URL Intelligence (structural / additive) ──
            "Suspicious Domain Keyword": {"score": 25, "confidence": 0.80},
            "Multi-Hyphen Domain": {"score": 15, "confidence": 0.70},
            "Long Domain": {"score": 10, "confidence": 0.65},

            # Base URL — context carrier only
            "URL": {"score": 0, "confidence": 0.10},
        }

    def evaluate(self, features: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Takes generic extracted features and maps them to a weighted risk score and
        confidence level.  Returns the features enriched with 'score' and 'confidence'.
        """
        evaluated_features = []

        # Track Contextual Urgency offsets so Generic Urgency overlaps can be suppressed
        contextual_intervals = [
            (f["start"], f["end"])
            for f in features if f["type"] == "Contextual Urgency"
        ]

        seen_matches: set = set()

        for feature in features:
            feat_type = feature["type"]
            start = feature["start"]
            end = feature["end"]

            # Suppress Generic Urgency when it overlaps with a Contextual Urgency span
            if feat_type == "Generic Urgency":
                overlap = any(
                    (start >= ctx_s and start < ctx_e) or
                    (end > ctx_s and end <= ctx_e)
                    for ctx_s, ctx_e in contextual_intervals
                )
                if overlap:
                    continue

            # Exact dedup by (type, start, end)
            match_key = f"{feat_type}:{start}:{end}"
            if match_key in seen_matches:
                continue
            seen_matches.add(match_key)

            rule = self.rules.get(feat_type, {"score": 0, "confidence": 0.0})

            evaluated_feature = feature.copy()
            evaluated_feature["score"] = rule["score"]
            evaluated_feature["confidence"] = rule["confidence"]

            # Only return features that carry risk or are URL context carriers
            if rule["score"] > 0 or feat_type == "URL":
                evaluated_features.append(evaluated_feature)

        return evaluated_features

from typing import List, Dict, Any

class ThreatSummaryGenerator:
    def __init__(self):
        pass

    def generate(self, risk_level: str, explained_features: List[Dict[str, Any]], ai_explanation: str = "") -> str:
        """
        Creates a high-level paragraph summarizing the threat landscape of the text.
        """
        if risk_level == "Low" and not explained_features:
            if ai_explanation:
                return f"This text appears normal. No immediate phrasing or link threats were detected. {ai_explanation} Maintain basic caution as no automated system is perfect."
            return "This text appears normal. No immediate phrasing or link threats were detected. Maintain basic caution as no automated system is perfect."

        if risk_level == "Low":
            if ai_explanation:
                return f"This text contains minor suspicious indicators, but no critical flags. {ai_explanation} Proceed with normal caution."
            return "This text contains minor suspicious indicators, but no critical flags. Proceed with normal caution."

        # Extract primary tactics
        tactics = list(set([f["type"] for f in explained_features]))
        
        # Determine the "Main attack technique"
        has_url_threats = any("URL" in t or "Link" in t or "Subdomain" in t or "Homograph" in t for t in tactics)
        has_urgency = any("Urgency" in t for t in tactics)
        has_fear_auth = "Fear Tactics" in tactics or "Authority Impersonation" in tactics
        has_cred_fin = "Credential Request" in tactics or "Financial Bait" in tactics

        sentences = []
        
        # Tactic summary
        tactic_descriptions = []
        if has_urgency:
            tactic_descriptions.append("creates a false sense of urgency")
        if has_fear_auth:
            tactic_descriptions.append("uses psychological pressure (fear or authority)")
        if has_cred_fin:
            tactic_descriptions.append("attempts to extract credentials or money")
        if has_url_threats:
            tactic_descriptions.append("contains highly deceptive or disguised links")

        if tactic_descriptions:
            if len(tactic_descriptions) > 1:
                tactics_str = ", ".join(tactic_descriptions[:-1]) + ", and " + tactic_descriptions[-1]
            else:
                tactics_str = tactic_descriptions[0]
            sentences.append(f"This email {tactics_str}.")
            
        # Add AI interpretation reasoning
        if ai_explanation:
            # We massage the output slightly if it isn't starting cleanly
            if not ai_explanation.startswith("The"):
                sentences.append(f"The {ai_explanation}")
            else:
                sentences.append(ai_explanation)
            
        # Add final overall risk summary sentence
        sentences.append(f"Overall risk is {risk_level.upper()}.")

        return " ".join(sentences)

from typing import List, Dict, Any

class ThreatSummaryGenerator:
    def __init__(self):
        pass

    def generate(self, risk_level: str, explained_features: List[Dict[str, Any]]) -> str:
        """
        Creates a high-level paragraph summarizing the threat landscape of the text.
        """
        if risk_level == "Low" and not explained_features:
            return "This text appears normal. No immediate phrasing or link threats were detected. Maintain basic caution as no automated system is perfect."

        if risk_level == "Low":
            return "This text contains minor suspicious indicators, but no critical flags. Proceed with normal caution."

        # Extract primary tactics
        tactics = list(set([f["type"] for f in explained_features]))
        
        # Determine the "Main attack technique"
        has_url_threats = any("URL" in t or "Link" in t or "Subdomain" in t or "Homograph" in t for t in tactics)
        has_urgency = any("Urgency" in t for t in tactics)
        has_fear_auth = "Fear Tactics" in tactics or "Authority Impersonation" in tactics
        has_cred_fin = "Credential Request" in tactics or "Financial Bait" in tactics

        sentences = []
        
        # Intro sentence based on risk
        if risk_level == "High":
             sentences.append(f"This email is classified as High Risk and is highly suspicious.")
        elif risk_level == "Medium":
             sentences.append(f"This email is classified as Medium Risk and requires careful inspection.")

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
            sentences.append(f"The text {tactics_str}.")

        # Actionable recommendation
        if has_url_threats and has_cred_fin:
             sentences.append("Do not click any links or provide personal information. Verify the sender's claims by visiting their official website directly through your browser.")
        elif has_url_threats:
             sentences.append("Avoid clicking links within this message as they likely lead to malicious sites.")
        elif has_cred_fin or has_urgency:
             sentences.append("Do not let the applied pressure trick you into acting; verify the request through a known, trusted secondary channel.")
        else:
             sentences.append("Proceed with extreme caution and verify the source before taking any action.")

        return " ".join(sentences)

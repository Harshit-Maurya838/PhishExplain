from typing import List, Dict, Any

class ThreatSummaryGenerator:
    def __init__(self):
        pass

    def generate(self, risk_level: str, explained_features: List[Dict[str, Any]], ai_explanation: str = "") -> str:
        """
        Creates a high-level paragraph summarising the full threat landscape,
        explicitly calling out impersonation, business pretext, and AI semantic signals.
        """
        if risk_level == "Low" and not explained_features:
            base = "This text appears normal. No immediate phrasing or link threats were detected."
            if ai_explanation:
                base += f" {ai_explanation}"
            return base + " Maintain basic caution as no automated system is perfect."

        if risk_level == "Low":
            base = "This text contains minor suspicious indicators, but no critical flags."
            if ai_explanation:
                base += f" {ai_explanation}"
            return base + " Proceed with normal caution."

        # ── Tactic Classification ──
        tactics = {f["type"] for f in explained_features}

        has_url_threats      = any("URL" in t or "Link" in t or "Domain" in t or "Subdomain" in t or "Homograph" in t for t in tactics)
        has_urgency          = any("Urgency" in t for t in tactics)
        has_fear_auth        = "Fear Tactics" in tactics or "Authority Impersonation" in tactics
        has_cred_fin         = "Credential Request" in tactics or "Financial Bait" in tactics
        has_impersonation    = "Institutional Impersonation" in tactics or "Authority Impersonation" in tactics
        has_business_pretext = "Business Pretext" in tactics
        has_portal_context   = "Portal Context" in tactics

        sentences = []

        # ── Impersonation sentence ──
        if has_impersonation:
            role_matches = [
                f["matched_text"] for f in explained_features
                if f["type"] in {"Institutional Impersonation", "Authority Impersonation"}
            ]
            roles_str = f'"{role_matches[0]}"' if role_matches else "an institutional team"
            sentences.append(
                f"This message impersonates {roles_str}, a classic social engineering tactic used "
                f"to exploit implicit trust in internal or official communications."
            )

        # ── Business pretext sentence ──
        if has_business_pretext:
            pretext_matches = [
                f["matched_text"] for f in explained_features if f["type"] == "Business Pretext"
            ]
            pretext_str = f'"{pretext_matches[0]}"' if pretext_matches else "a routine business operation"
            sentences.append(
                f"The email uses a business pretext ({pretext_str}) to make the request appear routine "
                f"and reduce the recipient's security instincts."
            )

        # ── Portal / credential harvesting sentence ──
        if has_portal_context or has_cred_fin:
            sentences.append(
                "It attempts to direct the recipient to an external link for credential entry or account action — "
                "a hallmark of credential harvesting attacks."
            )

        # ── Generic tactic descriptions ──
        tactic_descriptions = []
        if has_urgency:
            tactic_descriptions.append("creates a false sense of urgency")
        if has_fear_auth and not has_impersonation:
            tactic_descriptions.append("uses psychological pressure (fear or authority)")
        if has_url_threats:
            tactic_descriptions.append("contains deceptive or structurally suspicious links")

        if tactic_descriptions:
            if len(tactic_descriptions) > 1:
                tactics_str = ", ".join(tactic_descriptions[:-1]) + ", and " + tactic_descriptions[-1]
            else:
                tactics_str = tactic_descriptions[0]
            sentences.append(f"The message also {tactics_str}.")

        # ── AI semantic signal sentence ──
        if ai_explanation:
            cleaned = ai_explanation.strip()
            if not cleaned.startswith("The"):
                cleaned = "The " + cleaned
            sentences.append(cleaned)

        # ── Final risk verdict ──
        sentences.append(f"Overall risk is assessed as {risk_level.upper()}.")

        return " ".join(sentences)

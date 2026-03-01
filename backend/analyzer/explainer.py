from typing import List, Dict, Any

class Explainer:
    def __init__(self):
        # Explanations now mapped to multiple dimensions
        self.explanations = {
            "Contextual Urgency": {
                "why_used": "Attackers combine urgency keywords with action verbs to mentally force you into making a split-second decision before verifying the request.",
                "attacker_gain": "Bypasses your critical thinking, making you more likely to click malicious links or provide data under stress.",
                "how_to_verify": "Pause. Do not click the link. Open a new browser tab, navigating directly to the known official website of the service, and check for alerts."
            },
            "Generic Urgency": {
                "why_used": "Creates an artificial time constraint.",
                "attacker_gain": "Increases conversion rates of their attack by limiting your time to think.",
                "how_to_verify": "Assess the situation calmly. If it's truly urgent, there will be notifications on the service's primary website or app."
            },
            "Fear Tactics": {
                "why_used": "Induces panic by threatening negative consequences (like account deletion or legal action).",
                "attacker_gain": "Exploits human anxiety; people act quickly to resolve perceived severe threats.",
                "how_to_verify": "Remember that legitimate organizations rarely threaten immediate harsh actions via email. Check the service directly."
            },
            "Authority Impersonation": {
                "why_used": "Masquerades as a trusted entity (Admin, IT, Management) to demand compliance.",
                "attacker_gain": "Exploits the human tendency to obey authority figures implicitly.",
                "how_to_verify": "Contact the supposed sender (e.g. IT support) via a known, trusted secondary channel like a verified phone number or internal chat."
            },
            "Scarcity Manipulation": {
                "why_used": "Suggests a limited supply or time window for an opportunity.",
                "attacker_gain": "Forces you to act immediately out of fear of missing out (FOMO).",
                "how_to_verify": "Verify the offer on the company's official public channels."
            },
            "Credential Request": {
                "why_used": "A direct solicitation for your username, password, or verification code.",
                "attacker_gain": "Grants them immediate, unauthorized access to your account and sensitive data.",
                "how_to_verify": "Never log in from an email link. Navigate to the site manually."
            },
            "Financial Bait": {
                "why_used": "Uses money as a lure, either a fake invoice to pay or a promise of funds.",
                "attacker_gain": "Results in direct financial theft or deployment of malware via fake invoice attachments.",
                "how_to_verify": "Verify outstanding balances directly on the vendor's site. Do not trust wire transfer instructions sent via email."
            },
            "Suspicious URL (IP Based)": {
                 "why_used": "Uses a numerical IP address instead of a domain name.",
                 "attacker_gain": "Hides the true origin of the server, as legitimate companies always use domain names.",
                 "how_to_verify": "Do not browse to IP addresses sent in emails. Report the email to your security team."
            },
            "Suspicious URL (TLD)": {
                 "why_used": "Uses cheap, unvetted Top Level Domains (like .xyz, .top) heavily favored by cybercriminals.",
                 "attacker_gain": "Lowers operational costs for attackers while appearing like a real link.",
                 "how_to_verify": "Check if the legitimate company operates on a standard .com, .org, or country-specific domain."
            },
            "Shortened Link": {
                 "why_used": "Obscures the final destination of the URL.",
                 "attacker_gain": "Prevents you and automated scanners from seeing the malicious domain before clicking.",
                 "how_to_verify": "Avoid clicking. If essential, use a link expanding service (like CheckShortURL) to safely inspect the destination first."
            },
            "Fake Subdomain Impersonation": {
                 "why_used": "Places a trusted brand name (like 'paypal') in the subdomain of an attacker-controlled root domain (like 'secure-login.com').",
                 "attacker_gain": "Tricks the eye; a user glancing at the link sees the brand and assumes it's safe.",
                 "how_to_verify": "Examine the root domain (the part immediately preceding the top-level domain, e.g., the '.com'). If it's not the official brand name, it's fake."
            },
            "Homograph Attack (Punycode/Cyrillic)": {
                 "why_used": "Uses characters from different alphabets (like Cyrillic 'a') that look identical to Latin characters.",
                 "attacker_gain": "Visually spoofs a legitimate domain perfectly, bypassing normal visual inspection.",
                 "how_to_verify": "Type the domain manually into your browser instead of clicking or copying the link."
            },
            # ── Advanced URL Intelligence ──
            "Suspicious Domain Keyword": {
                "why_used": "Embeds trust-sounding words (secure, login, verify, banking, portal) directly into an attacker-controlled domain name.",
                "attacker_gain": "Tricks users into believing the domain belongs to a legitimate service, increasing the chance of credential submission.",
                "how_to_verify": "Read the root domain carefully (the part just before the .com/.org). If it is not the exact official brand name, it is fake."
            },
            "Multi-Hyphen Domain": {
                "why_used": "Uses multiple hyphens to construct long, deceptive domain names that mimic official services (e.g. secure-account-login-portal.com).",
                "attacker_gain": "Makes the domain appear descriptive and official while obscuring a malicious registrant.",
                "how_to_verify": "Legitimate services almost never have two or more hyphens in their root domain. Navigate directly to the known official website instead."
            },
            "Long Domain": {
                "why_used": "Registers abnormally long domain names to bury the real malicious part at the beginning while padding with familiar-looking text.",
                "attacker_gain": "Overwhelms the user's visual parsing of the URL, making them focus on the path rather than the suspicious domain.",
                "how_to_verify": "Hover over the link to reveal the full URL. Legitimate services use short, recognizable domain names."
            },
            # ── Contextual Composite Rules ──
            "Institutional Impersonation": {
                "why_used": "Impersonates a trusted internal or institutional team (IT, HR, Payroll, Support) to leverage authority and reduce suspicion.",
                "attacker_gain": "Employees naturally trust messages appearing to come from internal departments and are less likely to question requests from them.",
                "how_to_verify": "Contact the department directly via a known internal channel (phone, Slack, Teams). Never act on email requests that include links before verifying."
            },
            "Portal Context": {
                "why_used": "Uses action-triggering language (login, confirm, verify, portal, access) alongside an external link to create a fake login or verification page.",
                "attacker_gain": "Direct credential harvesting — the user believes they are logging into a real service portal.",
                "how_to_verify": "Never login from an email link. Open a new browser tab and navigate to the service's official URL manually."
            },
            "Business Pretext": {
                "why_used": "Frames the phishing attempt as a routine business operation (payroll update, system upgrade, document shared) to appear normal and non-threatening.",
                "attacker_gain": "Lowers the user's guard by disguising the attack as standard corporate procedure, bypassing security awareness training.",
                "how_to_verify": "Verify the supposed business action through an independent internal channel before clicking any links or downloading files."
            }
        }

    def explain(self, evaluated_features: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Takes evaluated features and enriches them with multidimensional explanations.
        """
        explained_features = []
        for feature in evaluated_features:
            explained_feature = feature.copy()
            feat_type = feature["type"]
            
            if feat_type == "URL":
                continue # Base URLs don't need rich explanation unless flagged
            
            # Fetch structured explainer data
            exp_data = self.explanations.get(feat_type, {
                "why_used": "Suspicious pattern detected.",
                "attacker_gain": "Potentially compromises user security.",
                "how_to_verify": "Proceed with extreme caution."
            })
            
            explained_feature["explanation"] = exp_data["why_used"]
            explained_feature["attacker_gain"] = exp_data["attacker_gain"]
            explained_feature["how_to_verify"] = exp_data["how_to_verify"]
            
            explained_features.append(explained_feature)
            
        return explained_features

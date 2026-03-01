import re
import logging
from typing import List, Dict, Any

# Configure local logger
logger = logging.getLogger("PhishExplain.FeatureExtractor")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

class FeatureExtractor:
    def __init__(self):
        # 1. Contextual Urgency
        urgency_words = r"(urgent|immediately|act now|action required|final notice|within 24 hours|asap|alert)"
        action_words = r"(login|verify|click|update|confirm|pay|transfer|download|reset)"

        self.contextual_urgency_pattern = re.compile(
            rf"\b({urgency_words}\W+(?:\w+\W+){{0,3}}{action_words})\b|\b({action_words}\W+(?:\w+\W+){{0,3}}{urgency_words})\b",
            re.IGNORECASE
        )

        self.generic_urgency_phrases = [
            r"urgent", r"immediately", r"act now", r"action required",
            r"within 24 hours", r"expires today", r"asap"
        ]

        # 2. Psychological Patterns
        self.fear_phrases = [
            r"unauthorized access", r"security alert", r"breach",
            r"compromised", r"stolen", r"police", r"legal action",
            r"account suspended", r"termination", r"deleted",
            r"deactivated", r"account will be locked"
        ]

        self.authority_phrases = [
            r"admin portal", r"it support", r"system administrator",
            r"management team", r"help desk", r"security team"
        ]

        self.scarcity_phrases = [
            r"last chance", r"limited time", r"expires today", r"few remaining"
        ]

        self.credential_phrases = [
            r"verify your account", r"login to continue", r"click here to reset",
            r"confirm your identity", r"update your billing", r"password reset",
            r"confirm your password", r"enter OTP", r"validate credentials"
        ]

        self.financial_phrases = [
            r"wire transfer", r"invoice attached", r"payment declined",
            r"unpaid bill", r"gift card", r"crypto", r"bitcoin"
        ]

        # 3. Institutional Impersonation Roles (used in combo with link presence)
        self.institutional_roles = [
            r"it services?", r"hr department", r"human resources?",
            r"customer support", r"payroll team", r"admin team",
            r"accounts? department", r"security team", r"support desk",
            r"helpdesk", r"it helpdesk", r"finance team", r"compliance team",
            r"information technology", r"service desk"
        ]

        # 4. Portal / Credential Context Action Words (used in combo with link presence)
        self.portal_action_words = [
            r"\blogin\b", r"\bportal\b", r"\bconfirm\b", r"\breview\b",
            r"\bverify\b", r"\baccess\b", r"\bupdate details?\b",
            r"\bsign[- ]?in\b", r"\bauthenticate\b"
        ]

        # 5. Business Pretext Phrases (used in combo with link presence)
        self.business_pretext_phrases = [
            r"system upgrade", r"payroll update", r"activity review",
            r"account synchronization", r"document shared",
            r"\bshortlisted\b", r"compliance update", r"policy update",
            r"system maintenance", r"account update required",
            r"mandatory training", r"onboarding process"
        ]

        # 6. URL Intelligence
        self.url_pattern = r"https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)"
        self.ip_url_pattern = r"https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
        self.suspicious_tlds = [r"\.xyz", r"\.top", r"\.ru", r"\.cn", r"\.info"]
        self.shortener_domains = [r"bit\.ly", r"tinyurl\.com", r"t\.co", r"goo\.gl", r"is\.gd"]
        self.suspicious_url_keywords = [r"login", r"verify", r"secure", r"update"]
        self.brand_impersonations = [r"paypal", r"microsoft", r"apple", r"google", r"amazon", r"netflix"]

        # Known official domains — exempt from security-keyword domain check
        self.known_official_domains = {
            "microsoft.com", "google.com", "apple.com", "amazon.com",
            "paypal.com", "netflix.com", "facebook.com", "twitter.com",
            "linkedin.com", "instagram.com", "github.com", "outlook.com",
            "office.com", "live.com", "hotmail.com", "yahoo.com",
            "chase.com", "bankofamerica.com", "wellsfargo.com",
            "adobe.com", "dropbox.com", "salesforce.com", "slack.com"
        }

        # Security-sounding keywords that attackers plant in domain names
        self.security_domain_keywords = [
            "secure", "login", "verify", "account", "banking",
            "portal", "update", "signin", "auth", "wallet",
            "payment", "alert", "support"
        ]

    def _match_phrases(self, text: str, phrases: List[str], feature_type: str, exact_only: bool = False) -> List[Dict[str, Any]]:
        matches = []
        for phrase in phrases:
            for match in re.finditer(phrase, text, re.IGNORECASE):
                matches.append({
                    "type": feature_type,
                    "matched_text": match.group(0),
                    "start": match.start(),
                    "end": match.end()
                })
        return matches

    def _get_root_domain(self, domain: str) -> str:
        """Extracts root domain (e.g. 'evil.secure-login.com' → 'secure-login.com')."""
        parts = domain.rstrip('.').split('.')
        if len(parts) >= 2:
            return f"{parts[-2]}.{parts[-1]}"
        return domain

    def _extract_urls(self, text: str) -> List[Dict[str, Any]]:
        matches = []
        for match in re.finditer(self.url_pattern, text):
            url = match.group(0)
            start = match.start()
            end = match.end()

            raw_domain = re.sub(r"^https?://", "", url).split('/')[0].lower()
            domain_part = raw_domain.split('@')[-1].split('?')[0]

            # ── Primary Classification (mutually exclusive; first match wins) ──

            if re.search(self.ip_url_pattern, url):
                matches.append({"type": "Suspicious URL (IP Based)", "matched_text": url, "start": start, "end": end})
                logger.info(f"URL: IP-based URL detected -> {url}")

            elif url.lower().startswith("http://"):
                matches.append({"type": "Insecure Link (HTTP)", "matched_text": url, "start": start, "end": end})
                logger.info(f"URL: Insecure HTTP link detected -> {url}")

            elif any(re.search(tld + r"(/|$)", url, re.IGNORECASE) for tld in self.suspicious_tlds):
                matches.append({"type": "Suspicious URL (TLD)", "matched_text": url, "start": start, "end": end})
                logger.info(f"URL: Suspicious TLD detected -> {url}")

            elif any(re.search(kw, url, re.IGNORECASE) for kw in self.suspicious_url_keywords):
                matches.append({"type": "Suspicious URL Keyword", "matched_text": url, "start": start, "end": end})
                logger.info(f"URL: Suspicious keyword in URL -> {url}")

            elif any(re.search(short, url, re.IGNORECASE) for short in self.shortener_domains):
                matches.append({"type": "Shortened Link", "matched_text": url, "start": start, "end": end})
                logger.info(f"URL: Shortened link detected -> {url}")

            else:
                parts = domain_part.split('.')
                if len(parts) > 2:
                    subdomains = ".".join(parts[:-2]).lower()
                    if any(brand in subdomains for brand in self.brand_impersonations):
                        matches.append({"type": "Fake Subdomain Impersonation", "matched_text": url, "start": start, "end": end})
                        logger.info(f"URL: Brand impersonation in subdomain -> {url}")
                    elif not all(ord(c) < 128 for c in domain_part):
                        matches.append({"type": "Homograph Attack (Punycode/Cyrillic)", "matched_text": url, "start": start, "end": end})
                        logger.info(f"URL: Homograph attack detected -> {url}")
                    else:
                        matches.append({"type": "URL", "matched_text": url, "start": start, "end": end})
                elif not all(ord(c) < 128 for c in domain_part):
                    matches.append({"type": "Homograph Attack (Punycode/Cyrillic)", "matched_text": url, "start": start, "end": end})
                    logger.info(f"URL: Homograph attack detected -> {url}")
                else:
                    matches.append({"type": "URL", "matched_text": url, "start": start, "end": end})

            # ── Structural Analysis (additive; layers on top of primary classification) ──

            root_domain = self._get_root_domain(domain_part)

            # Security-keyword in domain, but NOT an officially known domain
            if root_domain not in self.known_official_domains:
                if any(kw in domain_part for kw in self.security_domain_keywords):
                    matches.append({"type": "Suspicious Domain Keyword", "matched_text": url, "start": start, "end": end})
                    logger.info(f"URL: Security keyword in domain -> {domain_part}")

            # Two or more hyphens indicate obfuscated lookalike domains
            if domain_part.count('-') >= 2:
                matches.append({"type": "Multi-Hyphen Domain", "matched_text": url, "start": start, "end": end})
                logger.info(f"URL: Multi-hyphen domain ({domain_part.count('-')} hyphens) -> {domain_part}")

            # Unusually long domain (>20 chars) is a common attacker technique
            if len(domain_part) > 20:
                matches.append({"type": "Long Domain", "matched_text": url, "start": start, "end": end})
                logger.info(f"URL: Long domain ({len(domain_part)} chars) -> {domain_part}")

        return matches

    def extract_features(self, text: str) -> List[Dict[str, Any]]:
        logger.info("Starting feature extraction")
        features = []

        # 1. Contextual Urgency
        for match in self.contextual_urgency_pattern.finditer(text):
            features.append({
                "type": "Contextual Urgency",
                "matched_text": match.group(0),
                "start": match.start(),
                "end": match.end()
            })
            logger.info(f"Extracted Contextual Urgency: '{match.group(0)}'")

        # Generic urgency fallback (RuleEngine scores lower; deduplication via offsets)
        for match in self._match_phrases(text, self.generic_urgency_phrases, "Generic Urgency"):
            features.append(match)

        # 2. Psychological & Intent
        for feat in self._match_phrases(text, self.fear_phrases, "Fear Tactics"):
            features.append(feat)
            logger.info(f"Extracted Fear: '{feat['matched_text']}'")

        for feat in self._match_phrases(text, self.authority_phrases, "Authority Impersonation"):
            features.append(feat)
            logger.info(f"Extracted Authority: '{feat['matched_text']}'")

        for feat in self._match_phrases(text, self.scarcity_phrases, "Scarcity Manipulation"):
            features.append(feat)

        for feat in self._match_phrases(text, self.credential_phrases, "Credential Request"):
            features.append(feat)

        for feat in self._match_phrases(text, self.financial_phrases, "Financial Bait"):
            features.append(feat)

        # 3. URL Intelligence (run before combo checks so we can test link presence)
        url_features = self._extract_urls(text)
        features.extend(url_features)

        # Determine whether any external link exists in the text
        link_types = {
            "URL", "Insecure Link (HTTP)", "Suspicious URL (IP Based)",
            "Suspicious URL (TLD)", "Suspicious URL Keyword", "Shortened Link",
            "Fake Subdomain Impersonation", "Homograph Attack (Punycode/Cyrillic)",
            "Suspicious Domain Keyword", "Multi-Hyphen Domain", "Long Domain"
        }
        has_external_link = any(f["type"] in link_types for f in url_features)

        # 4. Contextual Composite Rules — only fire when a link is present
        if has_external_link:
            # 4a. Institutional Impersonation + Link
            for feat in self._match_phrases(text, self.institutional_roles, "Institutional Impersonation"):
                features.append(feat)
                logger.info(f"Extracted Institutional Impersonation: '{feat['matched_text']}'")

            # 4b. Portal / Credential Context + Link
            # Deduplicate by matched text (case-insensitive) to avoid repeated matches
            # of the same action word appearing multiple times or inside URLs
            seen_portal = set()
            for feat in self._match_phrases(text, self.portal_action_words, "Portal Context"):
                key = feat["matched_text"].lower()
                if key not in seen_portal:
                    seen_portal.add(key)
                    features.append(feat)
                    logger.info(f"Extracted Portal Context: '{feat['matched_text']}'")

            # 4c. Business Pretext + Link
            seen_pretext = set()
            for feat in self._match_phrases(text, self.business_pretext_phrases, "Business Pretext"):
                key = feat["matched_text"].lower()
                if key not in seen_pretext:
                    seen_pretext.add(key)
                    features.append(feat)
                    logger.info(f"Extracted Business Pretext: '{feat['matched_text']}'")

        logger.info(f"Feature extraction complete. Found {len(features)} raw features.")
        return features

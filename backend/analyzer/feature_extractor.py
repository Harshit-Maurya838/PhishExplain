import re
import logging
from typing import List, Dict, Any

# Configure local logger
logger = logging.getLogger("PhishExplain.FeatureExtractor")
logger.setLevel(logging.INFO)
# Basic console handler for visibility
if not logger.handlers:
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

class FeatureExtractor:
    def __init__(self):
        # 1. Contextual Urgency
        # We look for urgency words near action verbs.
        # This regex matches urgency words, then up to 3 words, then action words (or vice versa)
        urgency_words = r"(urgent|immediately|act now|action required|final notice|within 24 hours|asap|alert)"
        action_words = r"(login|verify|click|update|confirm|pay|transfer|download|reset)"
        
        # Matches "urgent login" or "login immediately" separated by up to 3 words
        self.contextual_urgency_pattern = re.compile(
            rf"\b({urgency_words}\W+(?:\w+\W+){{0,3}}{action_words})\b|\b({action_words}\W+(?:\w+\W+){{0,3}}{urgency_words})\b",
            re.IGNORECASE
        )

        # Base fallback urgency if not contextual (scored lower in engine)
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
        
        # 3. URL Intelligence
        self.url_pattern = r"https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)"
        self.ip_url_pattern = r"https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
        self.suspicious_tlds = [r"\.xyz", r"\.top", r"\.ru", r"\.net", r"\.cn", r"\.info"]
        self.shortener_domains = [r"bit\.ly", r"tinyurl\.com", r"t\.co", r"goo\.gl", r"is\.gd"]
        self.suspicious_url_keywords = [r"login", r"verify", r"secure", r"update"]
        
        # Fake subdomains (e.g., paypal.secure-login.com)
        # We look for common brand names used as subdomains on weird root domains
        self.brand_impersonations = [r"paypal", r"microsoft", r"apple", r"google", r"amazon", r"netflix"]

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

    def _extract_urls(self, text: str) -> List[Dict[str, Any]]:
        matches = []
        for match in re.finditer(self.url_pattern, text):
            url = match.group(0)
            start = match.start()
            end = match.end()
            
            # 1. Insecure HTTP Link
            if url.lower().startswith("http://"):
                matches.append({"type": "Insecure Link (HTTP)", "matched_text": url, "start": start, "end": end})
                logger.info(f"URL: Insecure HTTP link detected -> {url}")
                continue
                
            # 2. IP based
            if re.search(self.ip_url_pattern, url):
                matches.append({"type": "Suspicious URL (IP Based)", "matched_text": url, "start": start, "end": end})
                logger.info(f"URL: IP-based URL detected -> {url}")
                continue
                
            # 3. Suspicious TLD
            if any(re.search(tld + r"(/|$)", url, re.IGNORECASE) for tld in self.suspicious_tlds):
                 matches.append({"type": "Suspicious URL (TLD)", "matched_text": url, "start": start, "end": end})
                 logger.info(f"URL: Suspicious TLD detected -> {url}")
                 continue
                 
            # 4. Suspicious URL Keywords (e.g., login, verify in path)
            if any(re.search(keyword, url, re.IGNORECASE) for keyword in self.suspicious_url_keywords):
                matches.append({"type": "Suspicious URL Keyword", "matched_text": url, "start": start, "end": end})
                logger.info(f"URL: Suspicious keyword in URL detected -> {url}")
                continue
                 
            # 5. Shortener
            if any(re.search(short, url, re.IGNORECASE) for short in self.shortener_domains):
                 matches.append({"type": "Shortened Link", "matched_text": url, "start": start, "end": end})
                 logger.info(f"URL: Shortened link detected -> {url}")
                 continue
                 
            # Fake Subdomain (e.g., paypal.something.com)
            domain_part = re.sub(r"^https?://", "", url).split('/')[0]
            parts = domain_part.split('.')
            if len(parts) > 2: # Has subdomains
                subdomains = ".".join(parts[:-2]).lower() # Everything before domain.tld
                if any(brand in subdomains for brand in self.brand_impersonations):
                     matches.append({"type": "Fake Subdomain Impersonation", "matched_text": url, "start": start, "end": end})
                     logger.info(f"URL: Brand impersonation in subdomain detected -> {url}")
                     continue
                     
            # Homograph Detection (Basic check for mixed character sets/cyrillic lookalikes)
            # A very simplistic heuristic: check if ascii characters are mixed with non-ascii in the domain
            if not all(ord(c) < 128 for c in domain_part):
                matches.append({"type": "Homograph Attack (Punycode/Cyrillic)", "matched_text": url, "start": start, "end": end})
                logger.info(f"URL: Potential homograph attack detected -> {url}")
                continue

            # Generic URL
            matches.append({"type": "URL", "matched_text": url, "start": start, "end": end})
            
        return matches

    def extract_features(self, text: str) -> List[Dict[str, Any]]:
        logger.info("Starting feature extraction")
        features = []
        
        # 1. Contextual Urgency
        for match in self.contextual_urgency_pattern.finditer(text):
            # To avoid the nested generic urgency triggering, we'll mark this context
            features.append({
                "type": "Contextual Urgency",
                "matched_text": match.group(0),
                "start": match.start(),
                "end": match.end()
            })
            logger.info(f"Extracted Contextual Urgency: '{match.group(0)}'")
            
        # We still look for generic urgency, but the RuleEngine will score it lower.
        # Alternatively we could scrub context matches here to prevent overlap.
        # We will let RuleEngine handle deduping based on string offset overlaps.
        for match in self._match_phrases(text, self.generic_urgency_phrases, "Generic Urgency"):
             features.append(match)

        # 2. Psychological & Intent
        for fear in self._match_phrases(text, self.fear_phrases, "Fear Tactics"):
            features.append(fear)
            logger.info(f"Extracted Fear: '{fear['matched_text']}'")
            
        for auth in self._match_phrases(text, self.authority_phrases, "Authority Impersonation"):
             features.append(auth)
             logger.info(f"Extracted Authority: '{auth['matched_text']}'")
             
        for scarc in self._match_phrases(text, self.scarcity_phrases, "Scarcity Manipulation"):
             features.append(scarc)
             logger.info(f"Extracted Scarcity: '{scarc['matched_text']}'")

        for cred in self._match_phrases(text, self.credential_phrases, "Credential Request"):
             features.append(cred)
             
        for fin in self._match_phrases(text, self.financial_phrases, "Financial Bait"):
             features.append(fin)

        # 3. URLs
        url_features = self._extract_urls(text)
        features.extend(url_features)

        logger.info(f"Feature extraction complete. Found {len(features)} raw features.")
        return features

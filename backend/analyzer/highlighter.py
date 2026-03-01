from typing import List, Dict, Any

class Highlighter:
    def __init__(self):
        # We will wrap matched flagged phrases in HTML
        # Different classes can be used for different risk levels if desired later
        self.wrap_template = '<mark class="phish-flag {}">{}</mark>'
        
    def _get_class_for_type(self, type_str: str) -> str:
        # Simple mapping for CSS classes
        if type_str in ["Urgency Manipulation", "Fear Tactics", "Authority Impersonation", "Contextual Urgency"]:
            return "high-risk"
        if type_str in ["Suspicious URL Pattern", "Credential Request", "Fake Subdomain Impersonation", "Homograph Attack (Punycode/Cyrillic)", "Suspicious URL (IP Based)"]:
             return "critical-risk"
        if type_str in ["Financial Bait", "Scarcity Manipulation", "Suspicious URL (TLD)", "Shortened Link"]:
             return "medium-risk"
        return "low-risk"

    def highlight(self, original_text: str, features: List[Dict[str, Any]]) -> str:
        """
        Injects HTML highlights into the original text based on matched offsets.
        Replaces text from back to front to avoid offset shifting.
        """
        # Deduplicate features that have identical start/end offsets
        # If two features match the exact same string, we only want to highlight it once
        # to prevent nested HTML tags
        unique_spans = {}
        for feature in features:
            span_key = (feature["start"], feature["end"])
            # If there's an exact overlap, we keep the one with the higher risk
            # For simplicity, we just keep the first one seen.
            # In a true system, we'd rank them. Here Contextual Urgency was added first in extractor.
            if span_key not in unique_spans:
                 unique_spans[span_key] = feature
                 
        # Filter out features that are completely swallowed by another feature
        # E.g. Contextual Urgency "Verify your account immediately" (40, 71)
        # and Credential Request "Verify your account" (40, 59)
        # We only highlight the larger span to prevent broken nested HTML
        valid_features = []
        for span_key, feature in unique_spans.items():
            start, end = span_key
            is_swallowed = False
            for other_key, other_feat in unique_spans.items():
                o_start, o_end = other_key
                if (start, end) != (o_start, o_end):
                     # Is feature completely inside other_feat?
                     if start >= o_start and end <= o_end:
                         is_swallowed = True
                         break
            if not is_swallowed:
                valid_features.append(feature)

        # Sort features by start offset in reverse order
        sorted_features = sorted(valid_features, key=lambda x: x["start"], reverse=True)
        
        highlighted = original_text
        
        for feature in sorted_features:
            start = feature["start"]
            end = feature["end"]
            
            matched_segment = highlighted[start:end]
            css_class = self._get_class_for_type(feature["type"])
            replacement = self.wrap_template.format(css_class, matched_segment)
            
            highlighted = highlighted[:start] + replacement + highlighted[end:]
            
        return highlighted.replace('\n', '<br>')

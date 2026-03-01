import logging
from transformers import pipeline
import traceback

logger = logging.getLogger("PhishExplain.Analyzer.AIClassifier")

class AIClassifier:
    def __init__(self):
        self.model_name = "ealvaradob/bert-finetuned-phishing"
        self.model = None
        self._load_model()

    def _load_model(self):
        try:
            logger.info(f"Loading AI Classifier model: {self.model_name}")
            # We use CPU explicitly to keep it lightweight.
            # Using pipeline for easy inference.
            self.model = pipeline("text-classification", model=self.model_name, device=-1)
            logger.info("AI Classifier model loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load AI Classifier model: {e}")
            self.model = None

    def analyze(self, text: str) -> dict:
        """
        Analyzes the text using the ML model.
        Returns AI score, label, and confidence.
        If the model fails, returns a fallback safe score.
        """
        if not self.model:
            logger.warning("AI model not loaded. Returning fallback safe score.")
            return {
                "ai_score": 0.0,
                "label": "safe",
                "confidence": 0.0
            }

        if not text or len(text.strip()) == 0:
            return {
                "ai_score": 0.0,
                "label": "safe",
                "confidence": 1.0
            }

        try:
            # Truncate to maximum standard bert sequence length just in case
            # although pipeline handles most of this out of the box.
            max_chars = 512 * 4 
            input_text = text[:max_chars]

            # The pipeline returns a list containing dicts like:
            # [{'label': 'LABEL_1', 'score': 0.99}] 
            # or [{'label': 'phishing', 'score': 0.99}] depending on model config.
            # For 'mrm8488/bert-tiny-finetuned-phishing', LABEL_1 generally means phishing.
            results = self.model(input_text, truncation=True)
            result = results[0]

            raw_label = result.get('label', '').lower()
            confidence = result.get('score', 0.0)

            # Map the model's raw output to our standard output format.
            # LABEL_1 typically denotes the positive class (phishing) in binary classification fine-tunes
            if raw_label in ['label_1', 'phishing', '1', 'spam', 'malicious']:
                label = 'phishing'
                ai_score = confidence * 100
            else:
                label = 'safe'
                # If the model explicitly says 'safe' with 99% confidence, 
                # then ai_score (risk factor) is 1%.
                ai_score = (1.0 - confidence) * 100 

            logger.info(f"AI Classification complete. Raw Label: {raw_label}, Label: {label}, Confidence: {confidence:.2f}")

            return {
                "ai_score": round(ai_score, 2),
                "label": label,
                "confidence": round(confidence, 4)
            }
        except Exception as e:
            logger.error(f"Error during AI analysis: {e}")
            logger.debug(traceback.format_exc())
            return {
                "ai_score": 0.0,
                "label": "safe",
                "confidence": 0.0
            }

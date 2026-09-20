import logging
import math
import re
from typing import Tuple, Optional
from .model_config import ModelConfig

logger = logging.getLogger("InputScanner.ML")


class DebertaInjectionClassifier:
    """
    ML-based Prompt Injection Classifier utilizing pretrained DeBERTa.
    Features lazy weight loading, GPU/CPU autodetection, and robust fallback.
    """

    _instance = None
    _tokenizer = None
    _model = None
    _device = None
    _is_initialized = False
    _using_fallback = False

    def __init__(self, config: Optional[ModelConfig] = None):
        self.config = config or ModelConfig()

    @classmethod
    def get_instance(cls, config: Optional[ModelConfig] = None) -> "DebertaInjectionClassifier":
        if cls._instance is None:
            cls._instance = cls(config)
        return cls._instance

    def initialize(self) -> bool:
        """
        Loads the tokenizer and model weights lazily.
        Returns True if the PyTorch/HuggingFace model loaded successfully, False if using fallback.
        """
        if self._is_initialized:
            return not self._using_fallback

        try:
            import torch
            from transformers import AutoTokenizer, AutoModelForSequenceClassification

            # Determine device
            if self.config.device:
                device_str = self.config.device
            else:
                device_str = "cuda" if torch.cuda.is_available() else "cpu"
            self._device = torch.device(device_str)

            logger.info(f"Loading DeBERTa model: {self.config.model_name} on {self._device}...")
            self._tokenizer = AutoTokenizer.from_pretrained(self.config.model_name)
            self._model = AutoModelForSequenceClassification.from_pretrained(self.config.model_name)
            self._model.to(self._device)
            self._model.eval()

            self._using_fallback = False
            self._is_initialized = True
            logger.info("DeBERTa Prompt Injection classifier loaded successfully.")
            return True

        except Exception as e:
            logger.warning(
                f"Could not load HuggingFace DeBERTa model ({e}). "
                "Engaging semantic feature fallback classifier for high-availability."
            )
            self._using_fallback = True
            self._is_initialized = True
            return False

    def predict(self, text: str) -> Tuple[float, str]:
        """
        Classifies input text for prompt injection probability.
        Returns:
            - injection_probability (float): 0.0 to 1.0
            - label (str): 'INJECTION' or 'SAFE'
        """
        if not self._is_initialized:
            self.initialize()

        if not self._using_fallback and self._model is not None and self._tokenizer is not None:
            return self._predict_transformer(text)
        else:
            return self._predict_semantic_fallback(text)

    def _predict_transformer(self, text: str) -> Tuple[float, str]:
        """Runs inference via HuggingFace transformer model."""
        import torch

        try:
            inputs = self._tokenizer(
                text,
                truncation=True,
                max_length=self.config.max_length,
                padding=True,
                return_tensors="pt"
            )
            inputs = {k: v.to(self._device) for k, v in inputs.items()}

            with torch.no_grad():
                outputs = self._model(**inputs)
                logits = outputs.logits
                probabilities = torch.softmax(logits, dim=-1).squeeze(0).cpu().numpy()

            # Determine index for injection label
            id2label = getattr(self._model.config, "id2label", {0: "SAFE", 1: "INJECTION"})
            injection_idx = 1  # Default assumption

            for idx, label_name in id2label.items():
                upper_name = str(label_name).upper()
                if "INJ" in upper_name or "MALICIOUS" in upper_name or upper_name == "LABEL_1":
                    injection_idx = int(idx)
                    break

            injection_prob = float(probabilities[injection_idx])
            label = "INJECTION" if injection_prob >= self.config.injection_threshold else "SAFE"
            return round(injection_prob, 4), label

        except Exception as e:
            logger.error(f"Transformer inference error: {e}. Falling back to semantic classifier.")
            return self._predict_semantic_fallback(text)

    def _predict_semantic_fallback(self, text: str) -> Tuple[float, str]:
        """
        High-accuracy semantic feature classifier used when model weights or network
        connectivity are unavailable. Evaluates lexical entropy, instruction verbs,
        override density, and adversarial grammar signatures.
        """
        if not text or not text.strip():
            return 0.0, "SAFE"

        lower = text.lower()
        score = 0.0

        # Feature 1: Adversarial imperative sequences
        adversarial_pairs = [
            (r"\b(ignore|forget|disregard)\b.*\b(rule|instruction|prompt|guideline)s?\b", 0.45),
            (r"\b(act|pretend|behave)\b.*\b(as|like)\b.*\b(unrestricted|jailbreak|evil|dan)\b", 0.50),
            (r"\b(bypass|disable|override)\b.*\b(filter|security|safety|guardrail)s?\b", 0.45),
            (r"\b(show|reveal|print|echo)\b.*\b(system\s+prompt|initial\s+message)\b", 0.40),
            (r"\b(developer|debug|god)\s+mode\b", 0.45),
            (r"\b(do\s+anything\s+now)\b", 0.55),
        ]

        for pat, weight in adversarial_pairs:
            if re.search(pat, lower):
                score += weight

        # Feature 2: High density of command directives
        imperatives = ["must", "shall", "always", "never", "only", "immediately", "mandatory"]
        imperative_count = sum(1 for w in imperatives if re.search(rf"\b{w}\b", lower))
        if imperative_count >= 3:
            score += 0.15

        # Feature 3: Delimiter or markup spoofing
        if any(marker in text for marker in ["<|im_start|>", "[INST]", "---BEGIN", "System:"]):
            score += 0.35

        # Feature 4: Base64 / Hex token patterns
        if re.search(r"(?:[A-Za-z0-9+/]{4}){4,}={0,2}", text):
            score += 0.10

        # Normalize score into [0.0, 0.99] using sigmoid-like curve
        prob = 1.0 / (1.0 + math.exp(-6.0 * (score - 0.40))) if score > 0 else 0.02
        prob = max(0.0, min(0.99, round(prob, 4)))

        label = "INJECTION" if prob >= self.config.injection_threshold else "SAFE"
        return prob, label

import time
import asyncio
from typing import Union, Optional

from .schemas import ScanRequest, ScanResult
from .rules.rule_engine import RuleEngine
from .ml.classifier import DebertaInjectionClassifier
from .ml.model_config import ModelConfig
from .ensemble import EnsembleDecisionEngine


class InputInjectionScanner:
    """
    Main interface for the Input Injection Scanner.
    Orchestrates rule evaluation, DeBERTa classification, and ensemble decision making.
    """

    def __init__(
        self,
        model_config: Optional[ModelConfig] = None,
        block_threshold: float = 0.70,
        flag_threshold: float = 0.40,
    ):
        self.rule_engine = RuleEngine()
        self.classifier = DebertaInjectionClassifier.get_instance(model_config)
        self.ensemble = EnsembleDecisionEngine(
            block_threshold=block_threshold,
            flag_threshold=flag_threshold
        )

    def scan(self, request: Union[str, ScanRequest]) -> ScanResult:
        """
        Synchronously scans user input for prompt injections, jailbreaks, and overrides.
        """
        start_time = time.perf_counter()

        if isinstance(request, str):
            scan_req = ScanRequest(text=request)
        else:
            scan_req = request

        text = scan_req.text

        # 1. Evaluate heuristic rules & obfuscation
        rule_score, flagged_rules, attack_types = self.rule_engine.evaluate(text)

        # 2. Evaluate ML classifier
        ml_score, ml_label = self.classifier.predict(text)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # 3. Fuse signals into final decision
        result = self.ensemble.fuse(
            text=text,
            rule_score=rule_score,
            flagged_rules=flagged_rules,
            rule_attack_types=attack_types,
            ml_score=ml_score,
            ml_label=ml_label,
            sensitivity_override=scan_req.sensitivity_threshold,
            latency_ms=elapsed_ms
        )

        return result

    async def scan_async(self, request: Union[str, ScanRequest]) -> ScanResult:
        """
        Asynchronously scans user input, running inference in an executor to avoid
        blocking the event loop.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.scan, request)

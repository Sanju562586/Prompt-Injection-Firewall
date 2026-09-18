"""
Red-Team Module — Evaluator
Provides quantitative metrics and forensic failure analysis for firewall evaluations:
  - Detection Accuracy, Precision, Recall, F1 Score
  - Evasion / Bypass Rate
  - Confusion Matrix (TP, FP, TN, FN)
  - Category-by-Category Diagnostic Breakdown
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from audit.models import Decision, ScanRequest
from scanners.input_scanner import scan_input


class FirewallEvaluator:
    """Computes security metrics over benchmark evaluations."""

    def __init__(self, scanner_fn=None):
        self.scanner = scanner_fn or scan_input

    def evaluate_test_set(
        self,
        malicious_prompts: List[str],
        benign_prompts: List[str],
    ) -> Dict[str, Any]:
        """
        Evaluate full test set containing both attack prompts and clean user prompts.
        """
        tp = 0  # Attack correctly blocked/warned
        fn = 0  # Attack missed (allowed)
        tn = 0  # Benign correctly allowed
        fp = 0  # Benign incorrectly blocked/warned

        bypasses: List[Dict[str, Any]] = []
        false_alarms: List[Dict[str, Any]] = []

        # Evaluate malicious inputs
        for prompt in malicious_prompts:
            res = self.scanner(ScanRequest(text=prompt))
            if res.decision in (Decision.BLOCK, Decision.WARN):
                tp += 1
            else:
                fn += 1
                bypasses.append({
                    "prompt": prompt,
                    "decision": res.decision.value,
                    "score": res.score,
                    "reason": res.reason,
                })

        # Evaluate benign inputs
        for prompt in benign_prompts:
            res = self.scanner(ScanRequest(text=prompt))
            if res.decision == Decision.ALLOW:
                tn += 1
            else:
                fp += 1
                false_alarms.append({
                    "prompt": prompt,
                    "decision": res.decision.value,
                    "score": res.score,
                    "reason": res.reason,
                })

        total_malicious = len(malicious_prompts)
        total_benign = len(benign_prompts)
        total = total_malicious + total_benign

        recall = (tp / total_malicious) if total_malicious > 0 else 1.0
        precision = (tp / (tp + fp)) if (tp + fp) > 0 else 1.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        accuracy = ((tp + tn) / total) if total > 0 else 1.0
        evasion_rate = (fn / total_malicious) if total_malicious > 0 else 0.0
        fpr = (fp / total_benign) if total_benign > 0 else 0.0

        return {
            "summary": {
                "total_samples": total,
                "accuracy": round(accuracy * 100, 2),
                "precision": round(precision * 100, 2),
                "recall_tpr": round(recall * 100, 2),
                "f1_score": round(f1, 4),
                "evasion_rate": round(evasion_rate * 100, 2),
                "false_positive_rate": round(fpr * 100, 2),
            },
            "confusion_matrix": {
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn,
            },
            "bypasses": bypasses,
            "false_alarms": false_alarms,
        }

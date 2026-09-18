"""
Red-Team Module — Attack Suite Runner
Executes attack vectors against the LLM Firewall and evaluates detection efficacy.

Usage:
  python -m redteam.runner
  python -m redteam.runner --category direct_injection
  python -m redteam.runner --export report.json
"""

from __future__ import annotations
import argparse
import json
import sys
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

# Reconfigure stdout for UTF-8 on Windows if needed
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from audit.models import Decision, ScanRequest
from redteam.attacks import ATTACKS, ATTACKS_BY_CATEGORY
from scanners.input_scanner import scan_input

PASS_TAG = "[PASS]"
FAIL_TAG = "[FAIL]"


def run_suite(
    category: Optional[str] = None,
    attack_ids: Optional[List[str]] = None,
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    Programmatic execution of red-team suite.
    """
    targets = ATTACKS
    if category and category != "all":
        targets = ATTACKS_BY_CATEGORY.get(category, [a for a in targets if a.category.value == category])
    if attack_ids:
        target_ids = set(attack_ids)
        targets = [a for a in targets if a.id in target_ids]

    results: List[Dict[str, Any]] = []
    category_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "passed": 0, "failed": 0})

    start_time = time.perf_counter()

    for attack in targets:
        scan_res = scan_input(ScanRequest(text=attack.prompt, request_id=attack.id))
        passed = (scan_res.decision == attack.expected_decision)

        cat = attack.category.value
        category_stats[cat]["total"] += 1
        if passed:
            category_stats[cat]["passed"] += 1
        else:
            category_stats[cat]["failed"] += 1

        results.append({
            "id": attack.id,
            "category": cat,
            "description": attack.description,
            "prompt": attack.prompt,
            "expected_decision": attack.expected_decision.value,
            "actual_decision": scan_res.decision.value,
            "score": round(scan_res.score, 4),
            "risk_level": scan_res.risk_level.value,
            "passed": passed,
            "reason": scan_res.reason,
            "latency_ms": scan_res.latency_ms,
        })

    elapsed_s = round(time.perf_counter() - start_time, 2)
    total = len(results)
    passed_count = sum(1 for r in results if r["passed"])
    failed_count = total - passed_count
    detection_rate = round((passed_count / total * 100) if total > 0 else 0.0, 1)

    return {
        "total": total,
        "passed": passed_count,
        "failed": failed_count,
        "detection_rate": detection_rate,
        "elapsed_seconds": elapsed_s,
        "category_stats": dict(category_stats),
        "results": results,
    }


def run_cli():
    parser = argparse.ArgumentParser(description="LLM Firewall Red-Team Runner")
    parser.add_argument("--category", type=str, default=None, help="Filter by category")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-attack log")
    parser.add_argument("--export", type=str, default=None, help="Path to export JSON results")
    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("  LLM FIREWALL -- RED-TEAM BENCHMARK SUITE")
    print("=" * 70)

    summary = run_suite(category=args.category, verbose=not args.quiet)

    if not args.quiet:
        for r in summary["results"]:
            tag = PASS_TAG if r["passed"] else FAIL_TAG
            desc = r["description"][:45]
            print(f"  {tag:<7} [{r['id']}] {desc:<45} -> {r['actual_decision']} ({r['score']:.2f})")

    print("\n" + "-" * 70)
    print("  BREAKDOWN BY CATEGORY")
    print("-" * 70)

    for cat, stats in sorted(summary["category_stats"].items()):
        p = stats["passed"]
        t = stats["total"]
        rate = (p / t * 100) if t > 0 else 0.0
        bar = "#" * p + "." * (t - p)
        print(f"  {cat:<22} [{bar}] {p}/{t} ({rate:.0f}%)")

    overall_rate = summary["detection_rate"]
    print("\n" + "=" * 70)
    print(f"  TOTAL: {summary['passed']}/{summary['total']} attacks caught in {summary['elapsed_seconds']}s")
    print(f"  OVERALL ACCURACY: {overall_rate:.1f}%")
    print("=" * 70 + "\n")

    if args.export:
        with open(args.export, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print(f"Results exported to {args.export}\n")


if __name__ == "__main__":
    run_cli()

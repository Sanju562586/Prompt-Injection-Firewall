"""
Red-Team Test Runner
Runs all 50+ attack vectors through the firewall and reports detection accuracy.

Usage:
  python -m redteam.runner           # run all attacks
  python -m redteam.runner --quick   # skip classifier (faster, offline)

Output:
  - Per-attack: PASS/FAIL, decision, score, reason
  - Per-category summary: detection rate
  - Overall: total passed, failed, detection rate
"""

from __future__ import annotations
import argparse
import time
from collections import defaultdict

from firewall.models import ScanRequest, RedTeamResult, Decision
from firewall.scanner import input_scanner
from redteam.attacks import ATTACKS


def _color(text: str, code: str) -> str:
    """ANSI color helper for terminal output."""
    return f"\033[{code}m{text}\033[0m"

PASS_ICON = _color("✓ PASS", "32")
FAIL_ICON = _color("✗ FAIL", "31")
WARN_COL  = _color("WARN",  "33")
BLOCK_COL = _color("BLOCK", "31")
ALLOW_COL = _color("ALLOW", "32")

DECISION_COLOR = {
    Decision.BLOCK: BLOCK_COL,
    Decision.WARN:  WARN_COL,
    Decision.ALLOW: ALLOW_COL,
}


def run_all(verbose: bool = True) -> list[RedTeamResult]:
    """Run all attack vectors and return results."""
    results: list[RedTeamResult] = []

    print("\n" + "═" * 70)
    print("  LLM FIREWALL — RED-TEAM TEST SUITE")
    print("═" * 70)

    for attack in ATTACKS:
        scan_result = input_scanner.scan(
            ScanRequest(text=attack.prompt, request_id=attack.id)
        )

        passed = scan_result.decision == attack.expected_decision

        rt_result = RedTeamResult(
            attack=attack,
            actual_decision=scan_result.decision,
            score=scan_result.score,
            passed=passed,
            reason=scan_result.reason,
        )
        results.append(rt_result)

        if verbose:
            icon    = PASS_ICON if passed else FAIL_ICON
            decision_str = DECISION_COLOR.get(scan_result.decision, scan_result.decision.value)
            print(
                f"  {icon}  [{attack.id}] {attack.description[:45]:<45} "
                f"→ {decision_str}  ({scan_result.score:.2f})"
            )

    return results


def print_summary(results: list[RedTeamResult]) -> None:
    """Print category-level and overall summary."""
    by_category: dict[str, list[RedTeamResult]] = defaultdict(list)
    for r in results:
        by_category[r.attack.category.value].append(r)

    print("\n" + "─" * 70)
    print("  RESULTS BY CATEGORY")
    print("─" * 70)

    total_pass = 0
    total_fail = 0

    for category, cat_results in sorted(by_category.items()):
        passed = sum(1 for r in cat_results if r.passed)
        total  = len(cat_results)
        rate   = passed / total * 100
        bar    = _color("█" * passed, "32") + _color("░" * (total - passed), "31")
        print(f"  {category:<25} {bar}  {passed}/{total}  ({rate:.0f}%)")
        total_pass += passed
        total_fail += (total - passed)

    overall_rate = total_pass / (total_pass + total_fail) * 100

    print("\n" + "═" * 70)
    print(f"  OVERALL: {total_pass}/{total_pass + total_fail} attacks detected")
    print(f"  Detection Rate: {_color(f'{overall_rate:.1f}%', '32' if overall_rate >= 80 else '33')}")

    if total_fail > 0:
        print(f"\n  {_color('MISSED ATTACKS:', '31')}")
        for r in results:
            if not r.passed:
                print(f"    [{r.attack.id}] {r.attack.description}")
                print(f"          Expected: {r.attack.expected_decision.value}  Got: {r.actual_decision.value}  Score: {r.score:.2f}")

    print("═" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(description="LLM Firewall Red-Team Runner")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-attack output")
    args = parser.parse_args()

    start = time.perf_counter()
    results = run_all(verbose=not args.quiet)
    elapsed = time.perf_counter() - start

    print_summary(results)
    print(f"  Completed {len(results)} attacks in {elapsed:.1f}s\n")


if __name__ == "__main__":
    main()

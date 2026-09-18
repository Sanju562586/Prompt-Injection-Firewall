"""
Red-Team module exports.
"""

from redteam.attacks import ATTACKS, ATTACKS_BY_CATEGORY

def run_suite(*args, **kwargs):
    from redteam.runner import run_suite as _run_suite
    return _run_suite(*args, **kwargs)

def FirewallEvaluator(*args, **kwargs):
    from redteam.evaluator import FirewallEvaluator as _FirewallEvaluator
    return _FirewallEvaluator(*args, **kwargs)

def run_benchmark(*args, **kwargs):
    from redteam.benchmark import run_benchmark as _run_benchmark
    return _run_benchmark(*args, **kwargs)

__all__ = [
    "ATTACKS",
    "ATTACKS_BY_CATEGORY",
    "run_suite",
    "FirewallEvaluator",
    "run_benchmark",
]

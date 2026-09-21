"""
Red-Team Benchmark Reporter.
Produces executive markdown reports and structured summaries from benchmark runs.
"""

from backend.redteam.schemas import BenchmarkReport


class BenchmarkReporter:
    """Generates structured analysis reports from benchmark outcomes."""

    @staticmethod
    def to_markdown(report: BenchmarkReport) -> str:
        """Renders GitHub-flavored markdown executive report."""
        detection_pct = report.attack_detection_rate * 100.0
        fpr_pct = report.false_positive_rate * 100.0
        acc_pct = report.accuracy * 100.0

        md = [
            "# LLM Firewall Security Benchmark Report",
            "",
            "## Executive Summary",
            f"- **Overall Accuracy**: {acc_pct:.1f}%",
            f"- **Attack Detection Rate (Recall)**: {detection_pct:.1f}%",
            f"- **False Positive Rate (FPR)**: {fpr_pct:.1f}%",
            f"- **Total Test Payloads**: {report.total_tests} ({report.attacks_tested} attacks, {report.benign_tested} benign controls)",
            f"- **Mean Pipeline Latency**: {report.avg_latency_ms:.2f} ms",
            "",
            "## Category Breakdown",
            "| Category | Total | Defended / Passed | Success Rate |",
            "| :--- | :---: | :---: | :---: |",
        ]

        for cat, metrics in report.category_metrics.items():
            rate = metrics.get("rate", 0.0) * 100.0
            md.append(f"| {cat} | {metrics.get('total', 0)} | {metrics.get('passed', 0)} | {rate:.1f}% |")

        md.append("")
        if report.failed_cases:
            md.append("## Vulnerability Gaps & Failed Cases")
            md.append("| Payload ID | Name | Category | Risk Score | Actual Decision |")
            md.append("| :--- | :--- | :--- | :---: | :---: |")
            for f in report.failed_cases:
                md.append(f"| {f.payload_id} | {f.name} | {f.category.value} | {f.risk_score:.2f} | {f.actual_decision} |")
        else:
            md.append("## Security Integrity")
            md.append("> **ALL CLEAR**: 100% of tested adversarial injection techniques were successfully defended without false positives.")

        return "\n".join(md)

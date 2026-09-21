"""
Dashboard Service Layer.
Connects AuditLogger, SecurityPipeline, and RedTeamRunner to power the administrative dashboard.
"""

import time
import uuid
from typing import Any, Dict, List, Optional
from backend.audit_logger.logger import AuditLogger
from backend.audit_logger.schemas import AuditQueryFilters, AuditEventType
from backend.gateway.pipeline import SecurityPipeline
from backend.gateway.schemas import ChatCompletionRequest, ChatMessage
from backend.redteam.runner import RedTeamRunner
from backend.redteam.schemas import BenchmarkReport
from backend.dashboard.schemas import DashboardStats, SimulationRequest, SimulationResponse
from backend.input_scanner.rules.patterns import INJECTION_PATTERNS


class DashboardService:
    """Service provider for dashboard metrics, simulation, and rule inspection."""

    def __init__(
        self,
        audit_logger: Optional[AuditLogger] = None,
        pipeline: Optional[SecurityPipeline] = None,
        redteam_runner: Optional[RedTeamRunner] = None,
    ):
        self.audit_logger = audit_logger or AuditLogger.get_instance()
        self.pipeline = pipeline or SecurityPipeline()
        self.redteam_runner = redteam_runner or RedTeamRunner(pipeline=self.pipeline)

    def get_stats(self) -> DashboardStats:
        """Retrieves aggregated operational metrics."""
        summary = self.audit_logger.get_metrics_summary()
        total = summary.get("total_events", 0)
        decisions = summary.get("decisions", {})
        blocked = decisions.get("BLOCK", 0) + decisions.get("QUARANTINE", 0)
        allowed = decisions.get("ALLOW", 0) + decisions.get("FLAG", 0)

        # Count attack types from events
        all_events = self.audit_logger.storage.get_all()
        attack_types: Dict[str, int] = {}
        for e in all_events:
            for v in e.violations:
                short_v = v.split(":")[0].strip() if ":" in v else v
                attack_types[short_v] = attack_types.get(short_v, 0) + 1

        return DashboardStats(
            total_requests=total,
            total_blocked=blocked,
            total_allowed=allowed,
            block_rate_percent=summary.get("blocked_percentage", 0.0),
            avg_latency_ms=summary.get("avg_latency_ms", 0.0),
            avg_risk_score=summary.get("avg_risk_score", 0.0),
            risk_distribution=summary.get("risk_levels", {}),
            attack_type_breakdown=attack_types,
            system_status="OPERATIONAL",
            active_rules_count=len(INJECTION_PATTERNS),
        )

    async def simulate(self, req: SimulationRequest) -> SimulationResponse:
        """Executes an end-to-end sandbox simulation without persisting production side-effects."""
        start = time.perf_counter()
        req_id = f"sim-{uuid.uuid4().hex[:8]}"

        chat_req = ChatCompletionRequest(
            model=req.model,
            messages=[ChatMessage(role="user", content=req.prompt)],
            documents=req.documents,
        )

        success, completion_res, blocked_res = await self.pipeline.execute(chat_req, req_id)
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        if not success and blocked_res:
            risk_score = blocked_res.risk_score
            risk_level = blocked_res.risk_level.value
            decision = blocked_res.decision.value
            explanation = blocked_res.reason
            violations = blocked_res.violations
            completion_text = None
        elif completion_res and completion_res.security:
            sec = completion_res.security
            risk_score = sec.risk_score
            risk_level = sec.risk_level.value
            decision = sec.decision.value
            explanation = sec.explanation or "Payload cleared firewall thresholds."
            violations = sec.violations
            completion_text = completion_res.choices[0].message.content
        else:
            risk_score = 0.0
            risk_level = "LOW"
            decision = "ALLOW"
            explanation = "Clear"
            violations = []
            completion_text = "OK"

        input_v = [v for v in violations if "Input" in v]
        rag_v = [v for v in violations if "RAG" in v]
        output_v = [v for v in violations if "Output" in v]

        # Log simulation event to audit log for live activity feed
        self.audit_logger.log_event(
            event_type=AuditEventType.FIREWALL_BLOCK if decision == "BLOCK" else AuditEventType.FIREWALL_ALLOW,
            request_id=req_id,
            risk_score=risk_score,
            risk_level=risk_level,
            decision=decision,
            input_text=req.prompt,
            violations=violations,
            latency_ms=elapsed_ms,
            metadata={"simulation": True},
        )

        return SimulationResponse(
            request_id=req_id,
            risk_score=risk_score,
            risk_level=risk_level,
            decision=decision,
            explanation=explanation,
            input_violations=input_v,
            rag_violations=rag_v,
            output_violations=output_v,
            completion=completion_text,
            latency_ms=round(elapsed_ms, 2),
            breakdown={
                "risk_score": risk_score,
                "input_violations_count": len(input_v),
                "rag_violations_count": len(rag_v),
                "output_violations_count": len(output_v),
            }
        )

    def get_events(
        self,
        limit: int = 50,
        offset: int = 0,
        decision: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieves formatted audit trail records."""
        filters = AuditQueryFilters(
            limit=limit,
            offset=offset,
            decision=decision,
            risk_level=risk_level,
        )
        events = self.audit_logger.query(filters)
        return [e.model_dump() for e in events]

    def get_rules(self) -> List[Dict[str, Any]]:
        """Lists active rule definitions and pattern signatures."""
        return [
            {
                "rule_id": r["id"],
                "name": r["name"],
                "attack_type": r["attack_type"].value,
                "severity": r["severity"].value,
                "description": r["description"],
                "pattern": r["pattern"].pattern,
                "confidence": r["confidence"],
            }
            for r in INJECTION_PATTERNS
        ]

    async def run_benchmark(self) -> BenchmarkReport:
        """Executes red-team adversarial benchmark suite on demand."""
        return await self.redteam_runner.run_suite()

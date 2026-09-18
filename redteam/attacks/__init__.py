"""
Red-Team Attack Library
Aggregates all categorized attack vectors.
"""

from typing import Dict, List
from audit.models import AttackVector
from redteam.attacks.direct_injection import ATTACKS as DI_ATTACKS
from redteam.attacks.jailbreak import ATTACKS as JB_ATTACKS
from redteam.attacks.role_hijack import ATTACKS as RH_ATTACKS
from redteam.attacks.indirect_injection import ATTACKS as II_ATTACKS
from redteam.attacks.token_smuggling import ATTACKS as TS_ATTACKS
from redteam.attacks.pii_exfiltration import ATTACKS as PE_ATTACKS
from redteam.attacks.rag_poisoning import ATTACKS as RP_ATTACKS

ATTACKS_BY_CATEGORY: Dict[str, List[AttackVector]] = {
    "direct_injection": DI_ATTACKS,
    "jailbreak": JB_ATTACKS,
    "role_hijack": RH_ATTACKS,
    "indirect_injection": II_ATTACKS,
    "token_smuggling": TS_ATTACKS,
    "pii_exfiltration": PE_ATTACKS,
    "rag_poisoning": RP_ATTACKS,
}

# Unified list of all 55 attack vectors
ATTACKS: List[AttackVector] = (
    DI_ATTACKS + JB_ATTACKS + RH_ATTACKS + II_ATTACKS + TS_ATTACKS + PE_ATTACKS + RP_ATTACKS
)

__all__ = [
    "ATTACKS",
    "ATTACKS_BY_CATEGORY",
    "DI_ATTACKS",
    "JB_ATTACKS",
    "RH_ATTACKS",
    "II_ATTACKS",
    "TS_ATTACKS",
    "PE_ATTACKS",
    "RP_ATTACKS",
]

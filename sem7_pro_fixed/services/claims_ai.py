# services/claims_ai.py
# AI-assisted claims processing (NORMAL + VEHICLE with BARGAIN)

import hashlib
from typing import Dict, Any, List


class ClaimsAI:
    def __init__(self, model_path: str = None, demo: bool = True):
        self.demo = demo
        self.model_path = model_path

    # --------------------------------------------------
    # Utility
    # --------------------------------------------------
    def _stable_random(self, *args) -> float:
        m = hashlib.sha256("::".join(map(str, args)).encode()).hexdigest()
        return int(m[:8], 16) / 0xFFFFFFFF

    # --------------------------------------------------
    # NORMAL CLAIM (Documents)
    # --------------------------------------------------
    def evaluate(self, files: List[str], metadata: Dict[str, Any]) -> Dict[str, Any]:
        base = sum(self._stable_random(f) for f in files) / max(1, len(files))
        amt = float(metadata.get("claim_amount", 0))
        amt_norm = min(1.0, amt / (metadata.get("policy_sum_insured", 100000) + 1e-6))
        risk = 0.35 * base + 0.65 * amt_norm

        decision = (
            "Auto-Approve" if risk < 0.35
            else "Manual Review" if risk < 0.65
            else "Reject"
        )

        return {
            "risk_score": round(risk, 3),
            "decision": decision,
            "signals": {
                "claim_type": "normal",
                "amount_ratio": round(amt_norm, 3),
                "file_quality_proxy": round(base, 3),
            }
        }

    # --------------------------------------------------
    # VEHICLE DAMAGE ESTIMATION (STEP 1)
    # --------------------------------------------------
    def evaluate_vehicle_damage(
        self,
        image_path: str,
        vehicle_type: str
    ) -> Dict[str, Any]:
        """
        STEP 1:
        Estimate vehicle damage using YOLO
        (NO approval decision here)
        """
        from services.vehicle_damage_ai import assess_vehicle_damage

        damage = assess_vehicle_damage(image_path, vehicle_type)
        estimated = damage.get("estimated_cost", 0)

        return {
            "estimated_damage": estimated,
            "signals": {
                "claim_type": "vehicle",
                "vehicle_type": vehicle_type,
                "detected_damages": damage.get("detected_damages", []),
                "breakdown": damage.get("breakdown", []),
                "model": "YOLO Damage Detection"
            }
        }

    # --------------------------------------------------
    # VEHICLE CLAIM BARGAIN (STEP 2)
    # --------------------------------------------------
    def evaluate_bargain(
        self,
        ai_estimate: float,
        user_amount: float
    ) -> Dict[str, Any]:
        """
        STEP 2:
        Compare user claim vs AI estimate
        """

        if ai_estimate <= 0:
            return {
                "decision": "Manual Review",
                "risk_score": 0.6,
                "signals": {
                    "reason": "No detectable damage",
                    "ai_estimate": ai_estimate,
                    "user_amount": user_amount
                }
            }

        deviation = (user_amount - ai_estimate) / ai_estimate

        if deviation <= 0.10:
            decision = "Auto-Approve"
            risk = 0.15
        elif deviation <= 0.30:
            decision = "Manual Review"
            risk = 0.45
        else:
            decision = "Reject"
            risk = 0.80

        return {
            "decision": decision,
            "risk_score": round(risk, 2),
            "signals": {
                "claim_type": "vehicle",
                "ai_estimate": ai_estimate,
                "user_amount": user_amount,
                "deviation_pct": round(deviation * 100, 1),
                "rule": "Deviation-based negotiation"
            }
        }

    # --------------------------------------------------
    # 🔥 BACKWARD COMPATIBILITY (IMPORTANT)
    # --------------------------------------------------
    def evaluate_vehicle_claim(
        self,
        image_path: str,
        vehicle_type: str,
        claimed_amount: float
    ) -> Dict[str, Any]:
        """
        Compatibility wrapper so existing routes don't break
        """

        estimate = self.evaluate_vehicle_damage(image_path, vehicle_type)
        ai_cost = estimate.get("estimated_damage", 0)

        bargain = self.evaluate_bargain(
            ai_estimate=ai_cost,
            user_amount=claimed_amount
        )

        return {
            **bargain,
            "estimated_damage": ai_cost,
            "signals": {
                **estimate.get("signals", {}),
                **bargain.get("signals", {})
            }
        }

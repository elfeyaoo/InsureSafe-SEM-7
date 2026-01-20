# services/claims_ai.py
# AI-assisted claims processing
# NORMAL + VEHICLE (MULTI-IMAGE) + BARGAIN

import hashlib
from typing import Dict, Any, List, Union


class ClaimsAI:
    def __init__(self, model_path: str = None, demo: bool = True):
        self.demo = demo
        self.model_path = model_path

    # --------------------------------------------------
    # Utility
    # --------------------------------------------------
    def _stable_random(self, *args) -> float:
        """
        Stable pseudo-random value for demo heuristics
        """
        m = hashlib.sha256("::".join(map(str, args)).encode()).hexdigest()
        return int(m[:8], 16) / 0xFFFFFFFF

    # --------------------------------------------------
    # DOCUMENT CLAIM (NORMAL)
    # --------------------------------------------------
    def evaluate(
        self,
        files: List[str],
        metadata: Dict[str, Any]
    ) -> Dict[str, Any]:

        base = sum(self._stable_random(f) for f in files) / max(1, len(files))

        claimed_amt = float(metadata.get("claim_amount", 0))
        sum_insured = float(metadata.get("policy_sum_insured", 100000))

        amt_ratio = min(1.0, claimed_amt / (sum_insured + 1e-6))

        risk = 0.35 * base + 0.65 * amt_ratio

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
                "amount_ratio": round(amt_ratio, 3),
                "documents_used": len(files),
                "file_quality_proxy": round(base, 3),
                "rules": [
                    "Amount vs Sum Insured",
                    "Document consistency",
                    "Completeness check"
                ]
            }
        }

    # --------------------------------------------------
    # VEHICLE DAMAGE ESTIMATION (MULTI IMAGE)
    # --------------------------------------------------
    def evaluate_vehicle_damage(
        self,
        image_paths: Union[str, List[str]],
        vehicle_type: str
    ) -> Dict[str, Any]:
        """
        STEP 1:
        - Runs YOLO per image
        - Aggregates results
        - NO decision here
        """

        from services.vehicle_damage_ai import assess_vehicle_damage

        # Normalize input
        if isinstance(image_paths, str):
            image_paths = [image_paths]

        total_cost = 0
        all_damages = []
        breakdown = []

        for img in image_paths:
            result = assess_vehicle_damage(img, vehicle_type)

            total_cost += result.get("estimated_cost", 0)
            all_damages.extend(result.get("detected_damages", []))
            breakdown.extend(result.get("breakdown", []))

        # Average across images
        avg_cost = int(total_cost / max(1, len(image_paths)))

        severity = (
            "low" if avg_cost < 10000
            else "medium" if avg_cost < 30000
            else "high"
        )

        return {
            "estimated_damage": avg_cost,
            "severity": severity,
            "signals": {
                "claim_type": "vehicle",
                "vehicle_type": vehicle_type,
                "images_used": len(image_paths),
                "aggregation": "average",
                "detected_damages": list(set(all_damages)),
                "breakdown": breakdown,
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

        if ai_estimate <= 0:
            return {
                "decision": "Manual Review",
                "risk_score": 0.60,
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
    # BACKWARD COMPATIBILITY WRAPPER
    # --------------------------------------------------
    def evaluate_vehicle_claim(
        self,
        image_path: Union[str, List[str]],
        vehicle_type: str,
        claimed_amount: float
    ) -> Dict[str, Any]:

        estimate = self.evaluate_vehicle_damage(
            image_paths=image_path,
            vehicle_type=vehicle_type
        )

        ai_cost = estimate.get("estimated_damage", 0)

        bargain = self.evaluate_bargain(
            ai_estimate=ai_cost,
            user_amount=claimed_amount
        )

        return {
            **bargain,
            "estimated_damage": ai_cost,
            "severity": estimate.get("severity"),
            "signals": {
                **estimate.get("signals", {}),
                **bargain.get("signals", {})
            }
        }

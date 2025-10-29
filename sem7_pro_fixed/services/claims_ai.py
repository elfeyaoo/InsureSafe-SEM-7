# services/claims_ai.py
# AI-assisted claims processing stub: evaluates uploaded docs/images, estimates fraud risk, and suggests auto-approval.
import os, random, hashlib
from typing import Dict, Any, List

class ClaimsAI:
    def __init__(self, model_path: str = None, demo: bool = True):
        self.demo = demo
        self.model_path = model_path

    def _stable_random(self, *args) -> float:
        m = hashlib.sha256("::".join(map(str, args)).encode()).hexdigest()
        return int(m[:8], 16) / 0xFFFFFFFF

    def evaluate(self, files: List[str], metadata: Dict[str, Any]) -> Dict[str, Any]:
        if self.demo:
            # Create a stable pseudo risk score based on filenames + amount
            base = sum(self._stable_random(f) for f in files) / max(1, len(files))
            amt = float(metadata.get("claim_amount", 0))
            amt_norm = min(1.0, amt / (metadata.get("policy_sum_insured", 100000) + 1e-6))
            risk = 0.35 * base + 0.65 * amt_norm  # Tunable
            decision = "Auto-Approve" if risk < 0.35 else ("Manual Review" if risk < 0.65 else "Reject")
            return {
                "risk_score": round(float(risk), 3),
                "decision": decision,
                "signals": {
                    "amount_ratio": round(amt_norm, 3),
                    "file_quality_proxy": round(base, 3),
                    "rules": [
                        "Amount vs Sum Insured check",
                        "Duplicate file name heuristic",
                        "Basic completeness check"
                    ]
                }
            }
        else:
            # Real pipeline would:
            # - run CNN for doc/image authenticity
            # - run OCR consistency checks
            # - run a fraud classifier
            raise NotImplementedError("Real claims AI not implemented in this scaffold.")

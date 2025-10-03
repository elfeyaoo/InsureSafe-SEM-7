from dataclasses import dataclass
from typing import List, Dict

@dataclass
class Policy:
    id: str
    name: str
    min_age: int = 18
    max_age: int = 65
    min_income: int = 0
    max_income: int = 1_000_000_000
    premium: int = 0  # Premium for affordability check
    duration_years: int = 1
    description: str = ""
    category: str = "General"  # optional for future category-based recommendation

# Example catalog
POLICIES: List[Policy] = [
    Policy(id="LIFE_START", name="Life Starter Plan", min_age=18, max_age=30, min_income=0, max_income=600_000, premium=5_000, duration_years=5, description="Affordable life cover for young earners."),
    Policy(id="FAM_SECURE", name="Family Secure", min_age=25, max_age=50, min_income=300_000, max_income=2_000_000, premium=15_000, duration_years=10, description="Balanced premium with family add-ons."),
    Policy(id="SENIOR_CARE", name="Senior Care", min_age=50, max_age=70, min_income=0, max_income=2_000_000, premium=20_000, duration_years=5, description="Health-first coverage for seniors."),
    Policy(id="ELITE_PLUS", name="Elite Plus", min_age=25, max_age=65, min_income=1_500_000, max_income=1_000_000_000, premium=50_000, duration_years=15, description="High coverage with global benefits."),
    Policy(id="HEALTH_BASE", name="Health Basic", min_age=18, max_age=65, min_income=0, max_income=1_000_000_000, premium=10_000, duration_years=3, description="OPD + hospitalization coverage."),
]

def recommend_policies(age: int,
                       annual_income: int,
                       existing_premiums: int = 0,
                       existing_policy_count: int = 0,
                       max_policies_allowed: int = 5,
                       affordability_factor: float = 0.3) -> List[Dict]:
    """
    Recommend policies based on:
    - User age
    - Annual income
    - Existing premiums (affordability)
    - Existing number of policies (limit max policies)
    - Policy duration left (prefer shorter duration if user is older)
    - Scoring by age, income, affordability, and policy fit
    """

    candidates = []
    remaining_slots = max_policies_allowed - existing_policy_count
    if remaining_slots <= 0:
        return []  # no more policies can be recommended

    max_affordable = annual_income * affordability_factor - existing_premiums

    for p in POLICIES:
        # Age & income eligibility
        if not (p.min_age <= age <= p.max_age and p.min_income <= annual_income <= p.max_income):
            continue

        # Affordability check
        if p.premium > max_affordable:
            continue

        # Score calculation
        age_mid = (p.min_age + p.max_age) / 2
        income_mid = (p.min_income + p.max_income) / 2

        # Age fit: closer age to policy mid-age is better
        age_score = 1 / (1 + abs(age - age_mid))

        # Income fit
        income_score = 1 / (1 + abs(annual_income - income_mid) / (income_mid + 1))

        # Affordability weight
        afford_score = 1 if p.premium <= max_affordable else 0

        # Policy count preference: prioritize if user has fewer policies
        slot_score = remaining_slots / max_policies_allowed

        # Duration consideration: shorter duration better for older users
        duration_score = 1 / (1 + abs((p.duration_years + age_mid) - age))

        # Weighted total score
        total_score = (0.35 * age_score +
                       0.25 * income_score +
                       0.2 * afford_score +
                       0.1 * slot_score +
                       0.1 * duration_score)

        candidates.append({
            "id": p.id,
            "name": p.name,
            "premium": p.premium,
            "description": p.description,
            "score": round(float(total_score), 4)
        })

    # Sort descending by score and limit to remaining slots
    candidates.sort(key=lambda x: x["score"], reverse=True)
    return candidates[:remaining_slots]

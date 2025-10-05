def recommend_policies(age, annual_income, existing_premiums=0, existing_policy_count=0, max_total_premium=100_000):
    """
    Fetch policies from MongoDB and recommend based on age, income, and affordability.
    Scoring:
      - Closeness to policy's ideal age and income midpoint.
      - Penalize if existing premium or policy count is high.
    Returns top 5 recommended policies with their names and scores.
    """
    from db import policies_col
    recommendations = []

    try:
        policies = policies_col.find()
    except Exception:
        return []  # If DB is unavailable

    for p in policies:
        # Safely pull fields
        min_age = p.get("min_age", 0)
        max_age = p.get("max_age", 100)
        min_inc = p.get("min_income", 0)
        max_inc = p.get("max_income", 10**12)
        premium = p.get("premium_amount", 0)

        # Eligibility check
        if not (min_age <= age <= max_age and min_inc <= annual_income <= max_inc):
            continue

        # Affordability penalty
        if existing_premiums + premium > max_total_premium:
            affordability_penalty = 0.5  # reduce score if too expensive
        else:
            affordability_penalty = 1.0

        # Policy count penalty (more existing policies slightly reduce score)
        count_penalty = max(0.7, 1.0 - 0.05 * existing_policy_count)

        # Closeness scores
        age_mid = (min_age + max_age) / 2
        inc_mid = (min_inc + max_inc) / 2

        age_range = (max_age - min_age) or 1
        inc_range = (max_inc - min_inc) or 1

        age_score = 1 - abs(age - age_mid) / age_range
        inc_score = 1 - abs(annual_income - inc_mid) / inc_range

        total_score = max(0, (age_score + inc_score) * affordability_penalty * count_penalty)

        recommendations.append({
            "name": p.get("name", "Unnamed Policy"),
            "score": round(total_score, 3)
        })

    # Sort by score descending and return top 5
    recommendations.sort(key=lambda x: x["score"], reverse=True)
    return recommendations[:5]

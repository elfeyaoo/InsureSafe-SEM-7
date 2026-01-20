# services/vehicle_damage_ai.py

import os
from ultralytics import YOLO

# ----------------------------------
# Resolve absolute model path safely
# ----------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "static", "models", "trained.pt")

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"YOLO model not found at {MODEL_PATH}")

# Load model ONCE (important for performance)
model = YOLO(MODEL_PATH)

# ----------------------------------
# Damage → Base repair cost (₹)
# ----------------------------------
DAMAGE_COSTS = {
    "dent": 8000,
    "scratch": 3000,
    "crack": 15000,
    "broken_lamp": 10000,
    "shattered_glass": 25000,
    "flat_tire": 1500
}

# ----------------------------------
# Vehicle-type cost multipliers
# ----------------------------------
VEHICLE_MULTIPLIER = {
    "car": 1.0,
    "bike": 0.6
}

# ----------------------------------
# Severity multiplier (KEY FIX)
# ----------------------------------
def severity_multiplier(damage_types_count):
    if damage_types_count >= 6:
        return 2.5, "High"
    elif damage_types_count >= 4:
        return 1.8, "Medium"
    elif damage_types_count >= 2:
        return 1.3, "Low"
    return 1.0, "Low"


# ----------------------------------
# MAIN DAMAGE ASSESSMENT
# ----------------------------------
def assess_vehicle_damage(image_paths, vehicle_type):
    """
    image_paths: list[str] OR single image path
    vehicle_type: car / bike
    """

    if isinstance(image_paths, str):
        image_paths = [image_paths]

    detected_counts = {}      # damage → count
    confidence_log = {}       # damage → max confidence (for transparency)
    breakdown = []
    total_cost = 0

    vehicle_multiplier = VEHICLE_MULTIPLIER.get(vehicle_type, 1.0)

    # 🔍 Run YOLO on all images
    for img_path in image_paths:
        results = model(img_path, conf=0.01)  # ✅ REQUIRED CONF LEVEL

        for r in results:
            if not r.boxes:
                continue

            for box in r.boxes:
                label = model.names.get(int(box.cls))
                if label not in DAMAGE_COSTS:
                    continue

                conf = float(box.conf)

                detected_counts[label] = detected_counts.get(label, 0) + 1
                confidence_log[label] = max(confidence_log.get(label, 0), conf)

    # 💰 Base cost aggregation (NO confidence reduction)
    for damage, count in detected_counts.items():
        base_cost = DAMAGE_COSTS[damage]
        cost = base_cost * count
        total_cost += cost

        breakdown.append({
            "damage": damage,
            "count": count,
            "base_cost": base_cost,
            "max_confidence": round(confidence_log[damage], 2),
            "subtotal": cost
        })

    # 🚗 Vehicle multiplier
    total_cost *= vehicle_multiplier

    # 🔥 Severity multiplier
    sev_mult, severity = severity_multiplier(len(detected_counts))
    total_cost *= sev_mult

    return {
        "vehicle_type": vehicle_type,
        "images_used": len(image_paths),
        "detected_damages": detected_counts,
        "estimated_cost": int(total_cost),
        "severity": severity,
        "vehicle_multiplier": vehicle_multiplier,
        "severity_multiplier": sev_mult,
        "breakdown": breakdown,
        "model": "YOLOv8 Damage Detection"
    }

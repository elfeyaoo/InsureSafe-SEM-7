# services/vehicle_damage_ai.py

import os
from ultralytics import YOLO

# ----------------------------------
# Resolve absolute model path safely
# ----------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "static", "models", "trained.pt")

# Load model once
model = YOLO(MODEL_PATH)

DAMAGE_COSTS = {
    "dent": 8000,
    "scratch": 3000,
    "crack": 15000,
    "broken_lamp": 10000,
    "shattered_glass": 25000,
    "flat_tire": 1500
}

def assess_vehicle_damage(image_path, vehicle_type):
    results = model(image_path, conf=0.01)

    total_cost = 0
    breakdown = []
    detected = []

    for r in results:
        for box in r.boxes:
            cls = int(box.cls)
            label = model.names[cls]

            if label in DAMAGE_COSTS:
                cost = DAMAGE_COSTS[label]
                total_cost += cost
                breakdown.append({
                    "damage": label,
                    "cost": cost
                })
                detected.append(label)

    return {
        "vehicle_type": vehicle_type,
        "detected_damages": detected,
        "estimated_cost": total_cost,
        "breakdown": breakdown
    }

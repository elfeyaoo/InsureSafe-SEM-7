# services/ocr_verify.py
# Aadhaar-aware OCR & verification service (SAFE & PRODUCTION-READY)

import re
import cv2
from typing import Dict, Any
from PIL import Image

import easyocr
import pytesseract
import os

# -----------------------------
# Optional: Windows Tesseract
# -----------------------------
if os.name == "nt":
    pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"


class DocumentVerifier:
    def __init__(self, demo: bool = False):
        self.demo = demo

        if not self.demo:
            self.reader = easyocr.Reader(['en'], gpu=False)
        else:
            self.reader = None

    # -----------------------------
    # Image loading
    # -----------------------------
    def _load_image(self, path: str):
        img = cv2.imread(path)
        if img is None:
            raise ValueError("Invalid image file")
        return img

    # -----------------------------
    # OCR extraction
    # -----------------------------
    def extract_text(self, image_path: str) -> str:

        # 🔹 DEMO MODE (NO OCR)
        if self.demo:
            return (
                "Name: Rahul Sharma\n"
                "DOB: 1998-05-12\n"
                "Gender: Male\n"
                "Aadhaar: 1234 5678 9012"
            )

        img = self._load_image(image_path)
        img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)

        text = ""

        # 🔹 EasyOCR
        if self.reader:
            results = self.reader.readtext(img_rgb)
            if results:
                text = "\n".join([r[1] for r in results])

        # 🔹 Fallback to Tesseract
        if not text.strip():
            pil = Image.fromarray(img_rgb)
            text = pytesseract.image_to_string(pil)

        return text.strip()

    # -----------------------------
    # Aadhaar field extraction
    # -----------------------------
    def extract_fields(self, text: str) -> Dict[str, str]:
        fields = {}

        lines = [l.strip() for l in text.split("\n") if len(l.strip()) > 3]

        # ---- Name (skip govt headers) ----
        ignore_words = {"government", "authority", "india", "unique"}
        name_candidates = []

        for line in lines:
            lower = line.lower()
            if any(w in lower for w in ignore_words):
                continue
            alpha_ratio = sum(c.isalpha() for c in line) / len(line)
            if alpha_ratio > 0.6:
                name_candidates.append(line)

        if name_candidates:
            fields["name"] = max(name_candidates, key=len)

        # ---- DOB ----
        dob_match = re.search(
            r'(\d{2}[-/]\d{2}[-/]\d{4}|\d{4}[-/]\d{2}[-/]\d{2})',
            text
        )
        if dob_match:
            fields["dob"] = dob_match.group(1)

        # ---- Gender ----
        if re.search(r'\bfemale\b', text, re.I):
            fields["gender"] = "female"
        elif re.search(r'\bmale\b', text, re.I):
            fields["gender"] = "male"

        # ---- Aadhaar Number (ALL formats) ----
        uid_match = re.search(
            r'(\d{4}[\s-]?\d{4}[\s-]?\d{4})',
            text
        )
        if uid_match:
            fields["aadhaar"] = uid_match.group(1).replace("-", " ")

        return fields

    # -----------------------------
    # Normalization helper
    # -----------------------------
    def _norm(self, s: str) -> str:
        return re.sub(r'[^a-z0-9]', '', s.lower()) if s else ""

    # -----------------------------
    # Main validation API
    # -----------------------------
    def validate(self, image_path: str, expected: Dict[str, str]) -> Dict[str, Any]:

        text = self.extract_text(image_path)
        extracted = self.extract_fields(text)

        match = {}

        if extracted.get("name") and expected.get("name"):
            match["name"] = self._norm(extracted["name"]) == self._norm(expected["name"])

        if extracted.get("dob") and expected.get("dob"):
            match["dob"] = extracted["dob"] == expected["dob"]

        if extracted.get("gender") and expected.get("gender"):
            match["gender"] = extracted["gender"] == expected["gender"].lower()

        is_valid = bool(match) and all(match.values())

        return {
            "document_type": "AADHAAR",
            "extracted": extracted,
            "match": match,
            "is_valid": is_valid
        }

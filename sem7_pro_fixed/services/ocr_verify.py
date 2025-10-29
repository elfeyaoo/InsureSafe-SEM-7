# services/ocr_verify.py
# OCR + document classification interface with DEMO and REAL hooks.
import re, os
from typing import Dict, Any
from PIL import Image
import numpy as np

class DocumentVerifier:
    def __init__(self, demo: bool = True):
        self.demo = demo
        # In real mode, initialize OCR engine (pytesseract/easyocr) and a CNN classifier

    def extract_text(self, image_path: str) -> str:
        if self.demo:
            # DEMO: pretend OCR by returning a synthetic string dependent on file hash
            h = abs(hash(os.path.basename(image_path))) % 10000
            return f"Name: Alex Doe\nDOB: 1990-01-0{h % 9 + 1}\nID: ID{h:04d}\nType: ID_CARD"
        else:
            # Example with pytesseract (requires install and Tesseract runtime)
            # import pytesseract
            # text = pytesseract.image_to_string(Image.open(image_path))
            # return text
            raise NotImplementedError("Real OCR not implemented in this scaffold.")

    def classify_document(self, image_path: str) -> str:
        if self.demo:
            # DEMO: simple rule based
            return "ID_CARD"
        else:
            # Load CNN model and predict
            raise NotImplementedError("Real CNN doc classification not implemented in this scaffold.")

    def validate(self, image_path: str, expected: Dict[str, str]) -> Dict[str, Any]:
        text = self.extract_text(image_path)
        doc_type = self.classify_document(image_path)
        name = re.search(r"Name:\s*(.*)", text)
        dob = re.search(r"DOB:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})", text)
        idn = re.search(r"ID:\s*([A-Za-z0-9]+)", text)

        result = {
            "document_type": doc_type,
            "extracted": {
                "name": name.group(1).strip() if name else None,
                "dob": dob.group(1) if dob else None,
                "id": idn.group(1) if idn else None,
            },
            "match": {}
        }
        for key, val in expected.items():
            got = result["extracted"].get(key)
            result["match"][key] = (got is not None and val and val.lower() == got.lower())
        result["is_valid"] = all(result["match"].values()) if result["match"] else False
        return result

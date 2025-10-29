from deepface import DeepFace

class FaceVerifier:
    def __init__(self, model_name="ArcFace"):
        self.model_name = model_name

    def compare(self, id_photo_path: str, selfie_path: str):
        try:
            result = DeepFace.verify(
                img1_path=id_photo_path,
                img2_path=selfie_path,
                model_name=self.model_name,
                enforce_detection=True  # Auto-detects face
            )

            return {
                "match": result.get("verified", False),
                "similarity": float(result.get("distance", 0.0))
            }

        except Exception as e:
            print("DeepFace Error:", e)
            return {"match": False, "similarity": 0.0}

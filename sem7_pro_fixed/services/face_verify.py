# services/face_verify.py
# Interface for facial verification. Supports DEMO mode (no heavy deps) and REAL mode (TensorFlow/PyTorch).
import os
from typing import Tuple, Dict
from PIL import Image
import numpy as np

class FaceVerifier:
    def __init__(self, model_path: str = None, demo: bool = True):
        self.demo = demo
        self.model_path = model_path
        # In real mode, load your CNN model here (e.g., Siamese or embedding network)
        # Example:
        # import tensorflow as tf
        # self.model = tf.keras.models.load_model(model_path)

    def _cheap_embedding(self, img_path: str) -> np.ndarray:
        # Lightweight embedding for DEMO: downscale + normalize to vector
        img = Image.open(img_path).convert("L").resize((32, 32))
        arr = np.asarray(img, dtype=np.float32)
        arr = (arr - arr.mean()) / (arr.std() + 1e-6)
        return arr.flatten()

    def compare(self, id_photo_path: str, selfie_path: str) -> Dict[str, float]:
        if self.demo:
            emb1 = self._cheap_embedding(id_photo_path)
            emb2 = self._cheap_embedding(selfie_path)
            # Cosine similarity
            denom = (np.linalg.norm(emb1) * np.linalg.norm(emb2) + 1e-6)
            sim = float(np.dot(emb1, emb2) / denom)
            # Convert to 0..1
            score = (sim + 1) / 2
            match = score >= 0.72  # Tunable threshold
            return {"match": bool(match), "similarity": round(score, 4)}
        else:
            # Example real pipeline:
            # 1) Detect and align faces
            # 2) Get embeddings via CNN
            # 3) Cosine distance + threshold
            # This is a stub to be implemented with your chosen stack.
            raise NotImplementedError("Real CNN face verification not implemented in this scaffold.")

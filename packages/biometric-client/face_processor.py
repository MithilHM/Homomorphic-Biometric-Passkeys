"""Face processing and recognition using FaceNet and MTCNN."""

import cv2
import numpy as np
from facenet_pytorch import InceptionResnetV1, MTCNN
from PIL import Image


class FaceProcessor:
    """Handles face detection, alignment, and feature extraction."""

    def __init__(self):
        self.mtcnn = MTCNN(keep_all=True)
        self.facenet = InceptionResnetV1(pretrained='vggface2').eval()

    def detect_faces(self, image: np.ndarray) -> list:
        """Detect faces in an image using MTCNN."""
        # Convert to PIL Image if needed
        if isinstance(image, np.ndarray):
            image = Image.fromarray(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))

        boxes, probs = self.mtcnn.detect(image)
        return boxes.tolist() if boxes is not None else []

    def extract_features(self, image: np.ndarray) -> np.ndarray:
        """Extract face embeddings using FaceNet."""
        # Preprocess image
        if isinstance(image, np.ndarray):
            image = Image.fromarray(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))

        # Detect and align face
        face = self.mtcnn(image)
        if face is None:
            raise ValueError("No face detected in image")

        # Extract features
        embedding = self.facenet(face.unsqueeze(0))
        return embedding.detach().numpy().flatten()

    def compare_faces(self, features1: np.ndarray, features2: np.ndarray) -> float:
        """Compare two face embeddings and return similarity score."""
        # Cosine similarity
        similarity = np.dot(features1, features2) / (
            np.linalg.norm(features1) * np.linalg.norm(features2)
        )
        return float(similarity)

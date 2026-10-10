"""
Face Processing Service

Centralized service for all face operations:
- Face detection using OpenCV Haar Cascade (lightweight, no TensorFlow!)
- Embedding extraction using FaceNet (InceptionResnetV1)
- Face matching using Euclidean/Cosine distance

This is the REAL implementation - no placeholders!
"""

import base64
import io
import logging
import os
from typing import Tuple, Optional, List, Union
import numpy as np
import cv2
import torch
from PIL import Image

logger = logging.getLogger(__name__)

# Lazy-loaded models (heavy imports)
_face_cascade = None
_extractor = None


def get_face_cascade():
    """Get OpenCV face cascade detector (lightweight, no TensorFlow!)."""
    global _face_cascade
    if _face_cascade is None:
        import cv2
        # Use OpenCV's built-in Haar cascade
        cascade_path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
        _face_cascade = cv2.CascadeClassifier(cascade_path)
        logger.info("OpenCV Haar Cascade face detector initialized")
    return _face_cascade


def get_extractor():
    """Get FaceNet embedding extractor (lazy load)."""
    global _extractor
    if _extractor is None:
        from .embedding_extractor import EmbeddingExtractor
        _extractor = EmbeddingExtractor()
        logger.info("FaceNet extractor initialized")
    return _extractor


class FaceService:
    """
    Service for face detection, embedding extraction, and matching.
    
    Usage:
        service = FaceService()
        
        # Process image and get embedding
        success, result = service.process_image(base64_image_string)
        if success:
            embedding = result
        else:
            error_message = result
        
        # Compare two embeddings
        distance, confidence = service.compare_embeddings(emb1, emb2)
    """
    
    # Distance threshold for face matching
    # Lower = stricter matching, higher = more lenient
    # Typical FaceNet threshold: 0.6-1.0
    MATCH_THRESHOLD = 1.0
    
    def __init__(self):
        """Initialize face service."""
        self._face_cascade = None
        self._extractor = None
    
    @property
    def face_cascade(self):
        """Lazy-load OpenCV face cascade."""
        if self._face_cascade is None:
            self._face_cascade = get_face_cascade()
        return self._face_cascade
    
    @property
    def extractor(self):
        """Lazy-load FaceNet extractor."""
        if self._extractor is None:
            self._extractor = get_extractor()
        return self._extractor
    
    def decode_base64_image(self, base64_string: str) -> Tuple[bool, Union[np.ndarray, str]]:
        """
        Decode base64 image string to numpy array.
        
        Args:
            base64_string: Base64 encoded image (may include data URL prefix)
        
        Returns:
            (success, image_array_or_error_message)
        """
        try:
            # Remove data URL prefix if present
            if ',' in base64_string:
                base64_string = base64_string.split(',')[1]
            
            # Decode base64
            image_bytes = base64.b64decode(base64_string)
            
            # Open with PIL
            from PIL import Image
            image = Image.open(io.BytesIO(image_bytes))
            
            # Convert to RGB numpy array
            image_rgb = image.convert('RGB')
            image_array = np.array(image_rgb)
            
            logger.debug(f"Decoded image: {image_array.shape}")
            return True, image_array
            
        except Exception as e:
            logger.error(f"Image decode error: {e}")
            return False, f"Invalid image data: {str(e)}"
    
    def detect_face(self, image_array: np.ndarray) -> Tuple[bool, Union[dict, str]]:
        """
        Detect face in image using OpenCV Haar Cascade.
        
        Args:
            image_array: RGB image as numpy array (H, W, 3)
        
        Returns:
            (success, face_data_or_error_message)
            face_data: {'box': [x, y, w, h], 'confidence': 1.0}
        """
        try:
            import cv2
            
            # Convert to grayscale for detection
            gray = cv2.cvtColor(image_array, cv2.COLOR_RGB2GRAY)
            
            # Detect faces
            faces = self.face_cascade.detectMultiScale(
                gray,
                scaleFactor=1.1,
                minNeighbors=5,
                minSize=(80, 80),
                flags=cv2.CASCADE_SCALE_IMAGE
            )
            
            if len(faces) == 0:
                return False, "No face detected in image"
            
            # Get the largest face (by area)
            if len(faces) > 1:
                areas = [w * h for (x, y, w, h) in faces]
                best_idx = np.argmax(areas)
                best_face = faces[best_idx]
                logger.info(f"Multiple faces detected ({len(faces)}), using largest")
            else:
                best_face = faces[0]
            
            x, y, w, h = best_face
            
            # OpenCV Haar doesn't provide confidence, so we use 1.0
            face_data = {
                'box': [int(x), int(y), int(w), int(h)],
                'confidence': 1.0
            }
            
            logger.debug(f"Face detected: box={face_data['box']}")
            return True, face_data
            
        except Exception as e:
            logger.error(f"Face detection error: {e}")
            return False, f"Face detection failed: {str(e)}"
    
    def crop_and_align_face(self, image_array: np.ndarray, face_data: dict, target_size: int = 160) -> np.ndarray:
        """
        Crop and resize face region for FaceNet.
        
        Args:
            image_array: Full RGB image as numpy array
            face_data: Face detection result
            target_size: Output size (FaceNet expects 160x160)
        
        Returns:
            Cropped and resized face image as numpy array
        """
        from PIL import Image
        
        x, y, w, h = face_data['box']
        
        # Add padding around face (20% on each side)
        padding = int(max(w, h) * 0.2)
        x1 = max(0, x - padding)
        y1 = max(0, y - padding)
        x2 = min(image_array.shape[1], x + w + padding)
        y2 = min(image_array.shape[0], y + h + padding)
        
        # Crop
        face_crop = image_array[y1:y2, x1:x2]
        
        # Resize to target size
        face_pil = Image.fromarray(face_crop)
        face_resized = face_pil.resize((target_size, target_size), Image.BILINEAR)
        
        return np.array(face_resized)
    
    def extract_embedding(self, face_image: np.ndarray) -> np.ndarray:
        """
        Extract 512-dimensional embedding from face image.
        
        Args:
            face_image: Cropped face image (160x160x3)
        
        Returns:
            Normalized embedding vector (512,)
        """
        # Convert to tensor: [H, W, C] -> [C, H, W]
        # Use from_numpy for efficiency
        face_tensor = torch.from_numpy(face_image).float()
        face_tensor = face_tensor.permute(2, 0, 1)  # HWC -> CHW
        
        # Normalize to [0, 1]
        face_tensor = face_tensor / 255.0
        
        # Extract embedding
        embedding = self.extractor.extract_embedding(face_tensor)
        
        return embedding

    def warmup(self):
        """Run a dummy inference to warm up the models."""
        try:
            logger.info("Warming up biometric models...")
            dummy_image = np.zeros((160, 160, 3), dtype=np.uint8)
            self.extract_embedding(dummy_image)
            logger.info("Biometric models warmed up successfully")
        except Exception as e:
            logger.warning(f"Biometric warm-up failed: {e}")
    
    def process_image(self, base64_image: str) -> Tuple[bool, Union[np.ndarray, str]]:
        """
        Complete pipeline: decode image -> detect face -> extract embedding.
        
        Args:
            base64_image: Base64 encoded image string
        
        Returns:
            (success, embedding_or_error_message)
        """
        # Step 1: Decode image
        success, result = self.decode_base64_image(base64_image)
        if not success:
            return False, result
        image_array = result
        
        # Step 2: Detect face
        success, result = self.detect_face(image_array)
        if not success:
            return False, result
        face_data = result
        
        # Step 3: Crop and align face
        face_image = self.crop_and_align_face(image_array, face_data)
        
        # Step 4: Extract embedding
        try:
            embedding = self.extract_embedding(face_image)
            logger.info(f"Embedding extracted: shape={embedding.shape}, norm={np.linalg.norm(embedding):.4f}")
            return True, embedding
        except Exception as e:
            logger.error(f"Embedding extraction error: {e}")
            return False, f"Embedding extraction failed: {str(e)}"
    
    def compare_embeddings(self, embedding1: np.ndarray, embedding2: np.ndarray) -> Tuple[float, float]:
        """
        Compare two face embeddings.
        
        Args:
            embedding1: First face embedding (512,)
            embedding2: Second face embedding (512,)
        
        Returns:
            (distance, confidence)
            - distance: Euclidean distance (lower = more similar)
            - confidence: Match confidence as percentage (higher = more similar)
        """
        # Compute Euclidean distance
        distance = float(np.linalg.norm(embedding1 - embedding2))
        
        # Convert distance to confidence
        # Distance of 0 = 100% confidence
        # Distance of THRESHOLD = ~50% confidence
        # Distance > 2*THRESHOLD = ~0% confidence
        confidence = max(0.0, min(1.0, 1.0 - (distance / (2 * self.MATCH_THRESHOLD))))
        
        return distance, confidence
    
    def is_match(self, embedding1: np.ndarray, embedding2: np.ndarray) -> Tuple[bool, float, float]:
        """
        Check if two embeddings match.
        
        Args:
            embedding1: First face embedding
            embedding2: Second face embedding
        
        Returns:
            (is_match, distance, confidence)
        """
        distance, confidence = self.compare_embeddings(embedding1, embedding2)
        is_match = distance < self.MATCH_THRESHOLD
        return is_match, distance, confidence
    
    def find_best_match(
        self, 
        query_embedding: np.ndarray, 
        stored_embeddings: List[Tuple[str, np.ndarray]]
    ) -> Tuple[bool, Optional[str], float, float]:
        """
        Find the best matching template from a list.
        
        Args:
            query_embedding: Query face embedding
            stored_embeddings: List of (template_id, embedding) tuples
        
        Returns:
            (matched, template_id, distance, confidence)
        """
        if not stored_embeddings:
            return False, None, float('inf'), 0.0
        
        best_match_id = None
        best_distance = float('inf')
        
        for template_id, stored_embedding in stored_embeddings:
            distance, _ = self.compare_embeddings(query_embedding, stored_embedding)
            if distance < best_distance:
                best_distance = distance
                best_match_id = template_id
        
        confidence = max(0.0, min(1.0, 1.0 - (best_distance / (2 * self.MATCH_THRESHOLD))))
        is_match = best_distance < self.MATCH_THRESHOLD
        
        return is_match, best_match_id, best_distance, confidence


# Global singleton instance
_face_service = None

def get_face_service() -> FaceService:
    """Get global face service instance."""
    global _face_service
    if _face_service is None:
        _face_service = FaceService()
    return _face_service

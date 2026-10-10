"""Face Detection and Alignment using MTCNN"""

import cv2
import numpy as np
from PIL import Image
from facenet_pytorch import MTCNN
import math
from typing import Tuple, Dict, Optional, List
import torch


class FaceDetector:
    """Face detection and alignment using MTCNN with advanced preprocessing."""

    def __init__(self):
        """Initialize MTCNN detector with specified parameters."""
        self.detector = MTCNN(
            image_size=160,
            margin=20,
            min_face_size=40,
            thresholds=[0.6, 0.7, 0.7],
            factor=0.709,
            device='cpu'
        )

    def _compute_alignment_angle(self, landmarks: np.ndarray) -> float:
        """Compute rotation angle based on eye positions for face alignment."""
        # Extract eye coordinates (assuming MTCNN landmark order: left_eye, right_eye, nose, mouth_left, mouth_right)
        left_eye = landmarks[0]  # [x, y]
        right_eye = landmarks[1]  # [x, y]

        # Calculate angle between eyes
        dx = right_eye[0] - left_eye[0]
        dy = right_eye[1] - left_eye[1]
        angle = math.degrees(math.atan2(dy, dx))

        return angle

    def _align_face(self, image: np.ndarray, landmarks: np.ndarray, bbox: List[float]) -> np.ndarray:
        """Align face based on eye positions."""
        # Compute eye center
        left_eye = landmarks[0]
        right_eye = landmarks[1]
        eye_center = ((left_eye[0] + right_eye[0]) / 2, (left_eye[1] + right_eye[1]) / 2)

        # Compute alignment angle
        angle = self._compute_alignment_angle(landmarks)

        # Get rotation matrix
        M = cv2.getRotationMatrix2D(eye_center, angle, 1.0)

        # Apply rotation
        aligned = cv2.warpAffine(image, M, (image.shape[1], image.shape[0]))

        # Update bbox coordinates after rotation (simplified - using center of bbox)
        bbox_center = ((bbox[0] + bbox[2]) / 2, (bbox[1] + bbox[3]) / 2)

        # Transform bbox center
        center_homogeneous = np.array([bbox_center[0], bbox_center[1], 1.0])
        transformed_center = M @ center_homogeneous

        # Crop 160x160 region centered on face
        crop_size = 160
        x1 = int(transformed_center[0] - crop_size // 2)
        y1 = int(transformed_center[1] - crop_size // 2)
        x2 = x1 + crop_size
        y2 = y1 + crop_size

        # Ensure crop is within image bounds
        x1 = max(0, x1)
        y1 = max(0, y1)
        x2 = min(image.shape[1], x2)
        y2 = min(image.shape[0], y2)

        # Crop and resize if necessary
        cropped = aligned[y1:y2, x1:x2]
        if cropped.shape[0] != crop_size or cropped.shape[1] != crop_size:
            cropped = cv2.resize(cropped, (crop_size, crop_size))

        return cropped

    def _apply_clahe(self, image: np.ndarray) -> np.ndarray:
        """Apply Contrast Limited Adaptive Histogram Equalization."""
        # Convert to LAB color space for better CLAHE results
        lab = cv2.cvtColor(image, cv2.COLOR_RGB2LAB)
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        lab[:, :, 0] = clahe.apply(lab[:, :, 0])
        enhanced = cv2.cvtColor(lab, cv2.COLOR_LAB2RGB)
        return enhanced

    def _normalize_image(self, image: np.ndarray) -> np.ndarray:
        """Normalize pixel values to [-1, 1] range."""
        # Convert to float and normalize to [0, 1]
        normalized = image.astype(np.float32) / 255.0
        # Scale to [-1, 1]
        normalized = (normalized - 0.5) / 0.5
        return normalized

    def detect_and_align(self, image_path: str) -> Tuple[Optional[torch.Tensor], Optional[Dict]]:
        """
        Detect and align faces in an image.

        Args:
            image_path: Path to the input image

        Returns:
            Tuple of (aligned_face_tensor, metadata_dict) or (None, None) if no suitable face found

        Raises:
            FileNotFoundError: If image file doesn't exist
            ValueError: For various detection/alignment errors
        """
        try:
            # Load image
            image = Image.open(image_path).convert('RGB')
            image_np = np.array(image)

        except FileNotFoundError:
            raise FileNotFoundError(f"Image file not found: {image_path}")
        except Exception as e:
            raise ValueError(f"Error loading image: {e}")

        # Run face detection
        try:
            boxes, probs, landmarks = self.detector.detect(image_np, landmarks=True)
        except Exception as e:
            raise ValueError(f"Face detection failed: {e}")

        # Check if any faces detected
        if boxes is None or len(boxes) == 0:
            raise ValueError("No faces detected in the image")

        # Find face with highest confidence above threshold
        valid_faces = []
        for i, (box, prob, landmark) in enumerate(zip(boxes, probs, landmarks)):
            if prob > 0.95:  # High confidence threshold
                valid_faces.append((i, box, prob, landmark))

        if len(valid_faces) == 0:
            raise ValueError("No faces detected with sufficient confidence (>0.95)")

        if len(valid_faces) > 1:
            # Log warning but proceed with highest confidence face
            print(f"Warning: Multiple faces detected ({len(valid_faces)}), using highest confidence face")

        # Use the face with highest confidence
        best_face = max(valid_faces, key=lambda x: x[2])
        face_idx, bbox, confidence, landmark_points = best_face

        try:
            # Align face
            aligned_face = self._align_face(image_np, landmark_points, bbox)

            # Apply CLAHE
            enhanced_face = self._apply_clahe(aligned_face)

            # Normalize
            normalized_face = self._normalize_image(enhanced_face)

            # Convert to tensor
            face_tensor = torch.from_numpy(normalized_face).permute(2, 0, 1).float()

            # Prepare metadata
            metadata = {
                'bbox': bbox.tolist(),
                'confidence': float(confidence),
                'landmarks': {
                    'left_eye': landmark_points[0].tolist(),
                    'right_eye': landmark_points[1].tolist(),
                    'nose': landmark_points[2].tolist(),
                    'mouth_left': landmark_points[3].tolist(),
                    'mouth_right': landmark_points[4].tolist()
                },
                'image_path': image_path,
                'face_index': face_idx
            }

            return face_tensor, metadata

        except Exception as e:
            raise ValueError(f"Face alignment failed: {e}")

    def detect_multiple_faces(self, image_path: str, confidence_threshold: float = 0.95) -> List[Tuple[torch.Tensor, Dict]]:
        """
        Detect and align multiple faces in an image.

        Args:
            image_path: Path to the input image
            confidence_threshold: Minimum confidence for face detection

        Returns:
            List of (face_tensor, metadata) tuples for each detected face
        """
        try:
            # Load image
            image = Image.open(image_path).convert('RGB')
            image_np = np.array(image)

        except FileNotFoundError:
            raise FileNotFoundError(f"Image file not found: {image_path}")
        except Exception as e:
            raise ValueError(f"Error loading image: {e}")

        # Run face detection
        try:
            boxes, probs, landmarks = self.detector.detect(image_np, landmarks=True)
        except Exception as e:
            raise ValueError(f"Face detection failed: {e}")

        if boxes is None or len(boxes) == 0:
            return []

        results = []
        for i, (box, prob, landmark) in enumerate(zip(boxes, probs, landmarks)):
            if prob >= confidence_threshold:
                try:
                    # Align face
                    aligned_face = self._align_face(image_np, landmark, box)
                    enhanced_face = self._apply_clahe(aligned_face)
                    normalized_face = self._normalize_image(enhanced_face)
                    face_tensor = torch.from_numpy(normalized_face).permute(2, 0, 1).float()

                    metadata = {
                        'bbox': box.tolist(),
                        'confidence': float(prob),
                        'landmarks': {
                            'left_eye': landmark[0].tolist(),
                            'right_eye': landmark[1].tolist(),
                            'nose': landmark[2].tolist(),
                            'mouth_left': landmark[3].tolist(),
                            'mouth_right': landmark[4].tolist()
                        },
                        'image_path': image_path,
                        'face_index': i
                    }

                    results.append((face_tensor, metadata))

                except Exception as e:
                    print(f"Warning: Failed to process face {i}: {e}")
                    continue

        return results

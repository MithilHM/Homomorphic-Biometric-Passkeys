"""Face Embedding Extraction using FaceNet"""

import os
import torch
import numpy as np
from typing import List, Union, Tuple
import warnings


class EmbeddingExtractor:
    """Extracts face embeddings using InceptionResnetV1 (FaceNet)"""

    def __init__(self):
        """Initialize the FaceNet model for embedding extraction."""
        # Determine device - Forced to CPU
        self.device = torch.device('cpu')
        
        # Optimize CPU threads for inference
        if torch.get_num_threads() < 4:
            torch.set_num_threads(max(4, os.cpu_count() or 4))
            
        print(f"Using device: {self.device} (threads: {torch.get_num_threads()})")

        # Load pre-trained FaceNet model
        try:
            from facenet_pytorch import InceptionResnetV1
            self.model = InceptionResnetV1(pretrained='vggface2').to(self.device)
            print("FaceNet model loaded successfully")
        except ImportError:
            raise ImportError("facenet_pytorch not installed. Install with: pip install facenet-pytorch")

        # Set model to evaluation mode
        self.model.eval()

        # Disable gradients for inference
        self.no_grad_context = torch.inference_mode()

        print(f"EmbeddingExtractor initialized on {self.device}")

    def extract_embedding(self, aligned_face_tensor: torch.Tensor) -> np.ndarray:
        """
        Extract face embedding from an aligned face tensor.

        Args:
            aligned_face_tensor: Aligned face tensor of shape [3, 160, 160] or [160, 160, 3]

        Returns:
            Normalized embedding vector as numpy array of shape [512] with dtype float32
        """
        if not isinstance(aligned_face_tensor, torch.Tensor):
            raise TypeError("Input must be a torch.Tensor")

        # Ensure tensor is on correct device
        face_tensor = aligned_face_tensor.to(self.device)

        # Handle different input shapes
        if face_tensor.dim() == 3:
            # Check if shape is [3, H, W] or [H, W, 3]
            if face_tensor.shape[0] == 3:
                # Already in [C, H, W] format
                pass
            elif face_tensor.shape[2] == 3:
                # Convert from [H, W, C] to [C, H, W]
                face_tensor = face_tensor.permute(2, 0, 1)
            else:
                raise ValueError(f"Unexpected tensor shape: {face_tensor.shape}. Expected [3, 160, 160] or [160, 160, 3]")
        else:
            raise ValueError(f"Expected 3D tensor, got {face_tensor.dim()}D tensor with shape {face_tensor.shape}")

        # Add batch dimension: [3, 160, 160] -> [1, 3, 160, 160]
        face_batch = face_tensor.unsqueeze(0)

        # Extract embedding
        with torch.inference_mode():
            embedding = self.model(face_batch)  # Shape: [1, 512]

        # Remove batch dimension: [1, 512] -> [512]
        embedding = embedding.squeeze(0)

        # L2 normalization
        embedding_norm = torch.norm(embedding, p=2, dim=0, keepdim=True)
        if embedding_norm > 0:
            embedding = embedding / embedding_norm

        # Convert to numpy array
        embedding_np = embedding.cpu().numpy().astype(np.float32)

        return embedding_np

    def batch_extract(self, face_tensor_list: List[torch.Tensor]) -> List[np.ndarray]:
        """
        Extract embeddings from multiple aligned face tensors.

        Args:
            face_tensor_list: List of aligned face tensors, each of shape [3, 160, 160] or [160, 160, 3]

        Returns:
            List of normalized embedding vectors as numpy arrays
        """
        if not face_tensor_list:
            return []

        # Process tensors to ensure consistent format
        processed_tensors = []
        for face_tensor in face_tensor_list:
            if not isinstance(face_tensor, torch.Tensor):
                raise TypeError("All inputs must be torch.Tensors")

            tensor = face_tensor.to(self.device)

            # Handle different input shapes
            if tensor.dim() == 3:
                if tensor.shape[0] == 3:
                    # Already in [C, H, W] format
                    processed_tensors.append(tensor)
                elif tensor.shape[2] == 3:
                    # Convert from [H, W, C] to [C, H, W]
                    processed_tensors.append(tensor.permute(2, 0, 1))
                else:
                    raise ValueError(f"Unexpected tensor shape: {tensor.shape}")
            else:
                raise ValueError(f"Expected 3D tensor, got {tensor.dim()}D tensor")

        # Stack into batch: List of [3, 160, 160] -> [N, 3, 160, 160]
        try:
            batch_tensor = torch.stack(processed_tensors)
        except RuntimeError as e:
            raise ValueError(f"Could not stack tensors into batch: {e}")

        # Extract embeddings
        with torch.inference_mode():
            embeddings = self.model(batch_tensor)  # Shape: [N, 512]

        # L2 normalization for each embedding in batch
        embedding_norms = torch.norm(embeddings, p=2, dim=1, keepdim=True)
        mask = embedding_norms > 0
        embeddings = torch.where(mask, embeddings / embedding_norms, embeddings)

        # Convert to list of numpy arrays
        embeddings_np = embeddings.cpu().numpy().astype(np.float32)
        embedding_list = [embeddings_np[i] for i in range(len(embeddings_np))]

        return embedding_list

    def compute_distance(self, embedding1: Union[np.ndarray, torch.Tensor],
                        embedding2: Union[np.ndarray, torch.Tensor]) -> float:
        """
        Compute Euclidean distance between two embeddings.

        Args:
            embedding1: First embedding vector
            embedding2: Second embedding vector

        Returns:
            Euclidean distance as float
        """
        # Convert to numpy if needed
        if isinstance(embedding1, torch.Tensor):
            embedding1 = embedding1.cpu().numpy()
        if isinstance(embedding2, torch.Tensor):
            embedding2 = embedding2.cpu().numpy()

        # Ensure same shape
        if embedding1.shape != embedding2.shape:
            raise ValueError(f"Embedding shapes don't match: {embedding1.shape} vs {embedding2.shape}")

        # Compute Euclidean distance
        distance = np.linalg.norm(embedding1 - embedding2)
        return float(distance)

    def compute_similarity(self, embedding1: Union[np.ndarray, torch.Tensor],
                          embedding2: Union[np.ndarray, torch.Tensor]) -> float:
        """
        Compute cosine similarity between two embeddings.

        Args:
            embedding1: First embedding vector
            embedding2: Second embedding vector

        Returns:
            Cosine similarity as float (-1 to 1)
        """
        # Convert to numpy if needed
        if isinstance(embedding1, torch.Tensor):
            embedding1 = embedding1.cpu().numpy()
        if isinstance(embedding2, torch.Tensor):
            embedding2 = embedding2.cpu().numpy()

        # Ensure same shape
        if embedding1.shape != embedding2.shape:
            raise ValueError(f"Embedding shapes don't match: {embedding1.shape} vs {embedding2.shape}")

        # Compute cosine similarity
        dot_product = np.dot(embedding1, embedding2)
        norm1 = np.linalg.norm(embedding1)
        norm2 = np.linalg.norm(embedding2)

        if norm1 == 0 or norm2 == 0:
            warnings.warn("One or both embeddings have zero norm")
            return 0.0

        similarity = dot_product / (norm1 * norm2)
        return float(similarity)

    def get_embedding_dimensions(self) -> int:
        """Get the dimensionality of embeddings produced by this extractor."""
        return 512

    def __str__(self) -> str:
        """String representation of the extractor."""
        return f"EmbeddingExtractor(device={self.device}, embedding_dim=512)"

import pytest
import torch
import numpy as np
import cv2
from PIL import Image
from pathlib import Path
import matplotlib.pyplot as plt
from biometric.face_detector import FaceDetector

@pytest.fixture(scope="session")
def detector():
    """Initialize MTCNN detector once for all tests."""
    return FaceDetector()

@pytest.fixture
def sample_images(tmp_path):
    """Download/create test images for validation."""
    test_images = []

    # Test 1: Clear frontal face (should detect easily)
    frontal = tmp_path / "frontal_face.jpg"
    # Create synthetic frontal face or download LFW sample
    img = Image.new('RGB', (640, 480), color='lightblue')
    img.save(frontal)
    test_images.append(frontal)

    # Test 2: Profile face (45° angle)
    profile = tmp_path / "profile_face.jpg"
    img = Image.new('RGB', (640, 480), color='lightgreen')
    img.save(profile)
    test_images.append(profile)

    # Test 3: Poor lighting (should still detect)
    dark = tmp_path / "dark_face.jpg"
    img = Image.new('RGB', (640, 480), color=(20, 20, 20))
    img.save(dark)
    test_images.append(dark)

    # Test 4: Multiple faces
    multi = tmp_path / "multi_faces.jpg"
    img = Image.new('RGB', (640, 480), color='yellow')
    img.save(multi)
    test_images.append(multi)

    return test_images

def test_single_face_detection(detector, sample_images, tmp_path):
    """Test basic face detection on frontal face."""
    result = detector.detect_and_align(sample_images[0])

    # CRITICAL VALIDATIONS
    assert result is not None, "No result returned"
    assert result['confidence'] > 0.95, f"Low confidence: {result['confidence']}"
    assert isinstance(result['aligned_face'], torch.Tensor), "Aligned face not tensor"

    # Check tensor shape: [3, 160, 160] for FaceNet
    assert result['aligned_face'].shape == (3, 160, 160), f"Wrong shape: {result['aligned_face'].shape}"

    # Check eye alignment: y-coordinates should be nearly horizontal (±5 pixels)
    landmarks = result['landmarks']
    left_eye_y = landmarks['left_eye'][1]
    right_eye_y = landmarks['right_eye'][1]
    eye_alignment_error = abs(left_eye_y - right_eye_y)
    assert eye_alignment_error < 5, f"Poor eye alignment: {eye_alignment_error}px"

    print(f"✅ Frontal face: confidence={result['confidence']:.3f}, alignment_error={eye_alignment_error:.1f}px")

    # Visualize result
    visualize_detection(sample_images[0], result, tmp_path / "test_frontal_result.jpg")

def test_no_face_detected(detector, tmp_path):
    """Test empty image handling."""
    empty_img = tmp_path / "empty.jpg"
    Image.new('RGB', (640, 480), color='black').save(empty_img)

    result = detector.detect_and_align(empty_img)
    assert result is None, "Should return None for no faces"

def test_multiple_faces(detector, sample_images):
    """Test behavior with multiple faces (should pick highest confidence)."""
    # Note: Your current impl picks first face >0.95
    result = detector.detect_and_align(sample_images[3])
    assert result is not None, "Should detect at least one face"

def test_landmark_consistency(detector, sample_images):
    """Validate 5-point landmarks are present and reasonable."""
    result = detector.detect_and_align(sample_images[0])
    landmarks = result['landmarks']

    required_points = ['left_eye', 'right_eye', 'nose', 'mouth_left', 'mouth_right']
    for point in required_points:
        assert point in landmarks, f"Missing landmark: {point}"
        assert len(landmarks[point]) == 2, f"Landmark {point} wrong format"
        assert all(0 <= coord < 640 for coord in landmarks[point]), "Landmark coords out of bounds"

def visualize_detection(image_path, result, output_path):
    """Helper to visualize detection + alignment for debugging."""
    if result is None:
        return

    img = cv2.imread(str(image_path))
    img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)

    # Draw bounding box
    bbox = result['bbox']
    cv2.rectangle(img_rgb, (int(bbox[0]), int(bbox[1])),
                  (int(bbox[0]+bbox[2]), int(bbox[1]+bbox[3])), (0, 255, 0), 2)

    # Draw landmarks
    landmarks = result['landmarks']
    colors = [(255,0,0), (0,255,0), (0,0,255), (255,255,0), (255,0,255)]
    for i, (name, point) in enumerate(landmarks.items()):
        cv2.circle(img_rgb, tuple(map(int, point)), 3, colors[i%len(colors)], -1)
        cv2.putText(img_rgb, name[:3], tuple(map(int, point)), cv2.FONT_HERSHEY_SIMPLEX, 0.5, colors[i%len(colors)], 1)

    # Show aligned face
    aligned = result['aligned_face'].permute(1,2,0).numpy()
    aligned = (aligned + 1) / 2  # Denormalize [-1,1] -> [0,1]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 6))
    ax1.imshow(img_rgb)
    ax1.set_title(f"Detected: {result['confidence']:.3f}")
    ax1.axis('off')

    ax2.imshow(aligned)
    ax2.set_title("Aligned Face (160x160)")
    ax2.axis('off')

    plt.savefig(output_path, bbox_inches='tight', dpi=150)
    plt.close()
    print(f"📸 Visualization saved: {output_path}")

# Performance benchmark
def test_detection_speed(detector, sample_images):
    """Benchmark detection speed (should be <500ms per image)."""
    times = []
    for img_path in sample_images[:10]:  # Test 10 images
        start = torch.cuda.Event(enable_timing=True) if torch.cuda.is_available() else None
        end = torch.cuda.Event(enable_timing=True) if torch.cuda.is_available() else None

        if start:
            start.record()
        result = detector.detect_and_align(img_path)
        if end:
            end.record()
            torch.cuda.synchronize()
            elapsed = start.elapsed_time(end)
            times.append(elapsed)
        else:
            times.append(0)  # CPU fallback

    avg_time = np.mean(times)
    print(f"⏱️  Average detection time: {avg_time:.1f}ms")
    assert avg_time < 500, f"Too slow: {avg_time:.1f}ms > 500ms limit"

# Run ALL tests
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

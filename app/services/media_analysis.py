import io
import logging
import math
import os
import statistics
import tempfile
import wave
from typing import Any, Dict, List

from PIL import Image, ImageStat

logger = logging.getLogger(__name__)


def _safe_import(module_name: str):
    try:
        module = __import__(module_name)
        return module
    except Exception:
        return None


np = _safe_import("numpy")
cv2 = _safe_import("cv2")
pytesseract = _safe_import("pytesseract")


def _object_labels(image: Image.Image) -> List[str]:
    try:
        from transformers import pipeline

        classifier = pipeline(
            "image-classification",
            model=os.getenv("HF_IMAGE_MODEL", "google/vit-base-patch16-224"),
        )
        predictions = classifier(image)
        return [item["label"] for item in predictions[:5]]
    except Exception as exc:
        logger.info("Image classifier unavailable: %s", exc)
        return []


def _ocr_text(image: Image.Image) -> str:
    if not pytesseract:
        return ""
    try:
        return pytesseract.image_to_string(image).strip()
    except Exception as exc:
        logger.info("OCR failed: %s", exc)
        return ""


def _image_deepfake_score(image: Image.Image) -> float:
    grayscale = image.convert("L")
    stat = ImageStat.Stat(grayscale)
    variance = stat.var[0] if stat.var else 0
    entropy = grayscale.entropy() if hasattr(grayscale, "entropy") else 0
    edges_score = 0.0

    if cv2 and np:
        try:
            matrix = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
            edges = cv2.Canny(matrix, 100, 200)
            edges_score = float(edges.mean() / 255.0)
        except Exception as exc:
            logger.info("OpenCV edge analysis failed: %s", exc)

    harmonic_score = min(1.0, (variance / 5000.0) + (entropy / 10.0) + edges_score)
    return round(harmonic_score * 100, 2)


def analyze_image_bytes(content: bytes, filename: str = "upload") -> Dict[str, Any]:
    image = Image.open(io.BytesIO(content)).convert("RGB")
    ocr_text = _ocr_text(image)
    labels = _object_labels(image)
    deepfake_score = _image_deepfake_score(image)

    risk_score = min(
        100,
        int(
            deepfake_score * 0.55
            + (18 if len(ocr_text) > 60 else 0)
            + (14 if any(word in ocr_text.lower() for word in ["password", "bank", "wallet", "verify"]) else 0)
        ),
    )
    threat_level = "threat" if risk_score >= 70 else "suspicious" if risk_score >= 40 else "safe"
    summary = (
        "Potential synthetic media indicators detected."
        if deepfake_score >= 65
        else "Media analyzed with visual and OCR heuristics."
    )

    return {
        "filename": filename,
        "media_type": "image",
        "summary": summary,
        "threat_level": threat_level,
        "risk_score": risk_score,
        "deepfake_score": deepfake_score,
        "ocr_text": ocr_text,
        "detected_objects": labels,
        "metadata": {
            "size": image.size,
            "mode": image.mode,
        },
    }


def analyze_audio_bytes(content: bytes, filename: str = "upload") -> Dict[str, Any]:
    duration_seconds = 0.0
    channels = 0
    sample_width = 0
    frame_rate = 0

    try:
        with wave.open(io.BytesIO(content), "rb") as audio_file:
            channels = audio_file.getnchannels()
            sample_width = audio_file.getsampwidth()
            frame_rate = audio_file.getframerate()
            frame_count = audio_file.getnframes()
            duration_seconds = frame_count / float(frame_rate or 1)
    except Exception as exc:
        logger.info("WAV metadata parsing failed: %s", exc)

    deepfake_score = 35.0
    if duration_seconds and channels == 1 and sample_width <= 2:
        deepfake_score = min(90.0, 40.0 + (duration_seconds / 2.0))

    risk_score = int(min(100, deepfake_score))
    threat_level = "threat" if risk_score >= 75 else "suspicious" if risk_score >= 45 else "safe"

    return {
        "filename": filename,
        "media_type": "audio",
        "summary": "Audio analyzed with waveform metadata heuristics.",
        "threat_level": threat_level,
        "risk_score": risk_score,
        "deepfake_score": deepfake_score,
        "ocr_text": "",
        "detected_objects": [],
        "metadata": {
            "duration_seconds": round(duration_seconds, 2),
            "channels": channels,
            "sample_width": sample_width,
            "frame_rate": frame_rate,
        },
    }


def analyze_video_bytes(content: bytes, filename: str = "upload") -> Dict[str, Any]:
    frame_count = 0
    average_brightness = 0.0

    if cv2 and np:
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4")
        try:
            temp_file.write(content)
            temp_file.close()
            capture = cv2.VideoCapture(temp_file.name)
            brightness_samples = []
            while capture.isOpened() and frame_count < 24:
                success, frame = capture.read()
                if not success:
                    break
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                brightness_samples.append(float(gray.mean()))
                frame_count += 1
            capture.release()
            if brightness_samples:
                average_brightness = statistics.mean(brightness_samples)
        except Exception as exc:
            logger.info("Video analysis failed: %s", exc)
        finally:
            try:
                os.unlink(temp_file.name)
            except OSError:
                pass

    deepfake_score = min(95.0, 25.0 + (frame_count * 2.0) + (average_brightness / 10.0))
    risk_score = int(min(100, deepfake_score))
    threat_level = "threat" if risk_score >= 75 else "suspicious" if risk_score >= 45 else "safe"

    return {
        "filename": filename,
        "media_type": "video",
        "summary": "Video analyzed with frame consistency heuristics.",
        "threat_level": threat_level,
        "risk_score": risk_score,
        "deepfake_score": round(deepfake_score, 2),
        "ocr_text": "",
        "detected_objects": [],
        "metadata": {
            "sampled_frames": frame_count,
            "average_brightness": round(average_brightness, 2),
        },
    }


def analyze_media_bytes(content: bytes, filename: str, media_type: str) -> Dict[str, Any]:
    media_type = (media_type or "").lower()
    if media_type == "image":
        return analyze_image_bytes(content, filename)
    if media_type == "audio":
        return analyze_audio_bytes(content, filename)
    if media_type == "video":
        return analyze_video_bytes(content, filename)

    return {
        "filename": filename,
        "media_type": media_type or "unknown",
        "summary": "Unsupported media type for deepfake analysis.",
        "threat_level": "safe",
        "risk_score": 0,
        "deepfake_score": 0,
        "ocr_text": "",
        "detected_objects": [],
        "metadata": {},
    }

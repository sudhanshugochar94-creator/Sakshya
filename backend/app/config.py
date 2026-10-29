"""Central configuration. Thresholds here are *configurable engineering parameters*,
not APH values. APH-derived numbers live only in versioned rule packs."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("SAKSHYA_DATA_DIR") or os.environ.get("PRAMAAN_DATA_DIR") or BASE_DIR / "data")
UPLOAD_DIR = DATA_DIR / "uploads"          # originals: immutable once written
DERIVED_DIR = DATA_DIR / "derived"         # overlays, rasterised pages, etc.
DB_PATH = DATA_DIR / "sakshya.db"

TOOL_VERSION = "sakshya-core/1.1.0"
LOW_CONFIDENCE_THRESHOLD = 0.80            # critical OCR/extraction fields below this -> needs_review
EXPIRY_WARNING_DAYS = 60                   # configurable warning window
NEAR_DUP_PHASH_DISTANCE = 6                # hamming distance threshold (visible in UI)
NEAR_DUP_TEXT_SIMILARITY = 0.90
GPS_TOLERANCE_KM = 0.5                     # configurable, not an APH value
AREA_TOLERANCE_PCT = 5.0                   # configurable, not an APH value
MIN_IMAGE_SIDE_PX = 640
MIN_BLUR_VARIANCE = 60.0
ALERT_ESCALATION_HOURS = 24
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
ALLOWED_EXT = {".pdf", ".png", ".jpg", ".jpeg", ".mp4"}
MAX_RETRIES = 2
CORS_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("SAKSHYA_ALLOWED_ORIGINS", "*").split(",")
    if origin.strip()
]

for d in (DATA_DIR, UPLOAD_DIR, DERIVED_DIR):
    d.mkdir(parents=True, exist_ok=True)

# Optional LLM explanation layer (off by default). The model may ONLY re-word an already validated finding;
# it never sees raw documents, never changes a status and is never the source of a verdict.
LLM_PROVIDER = os.environ.get("SAKSHYA_LLM", "off")            # off | anthropic
LLM_MODEL = os.environ.get("SAKSHYA_LLM_MODEL", "claude-haiku-5-5")
LLM_TIMEOUT_S = 12

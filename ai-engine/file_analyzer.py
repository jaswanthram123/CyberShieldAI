
import hashlib
from pathlib import Path

MAX_FILE_SIZE = 10 * 1024 * 1024

DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1",
    ".vbs", ".js", ".jar", ".scr", ".msi",
    ".hta", ".com"
}

SUSPICIOUS_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".iso",
    ".img", ".lnk", ".wsf"
}

DOUBLE_EXTENSION_TARGETS = {
    ".pdf", ".jpg", ".jpeg", ".png",
    ".txt", ".doc", ".docx", ".xlsx"
}

FILE_SIGNATURES = {
    "PDF": [b"%PDF-"],
    "PNG": [b"\x89PNG\r\n\x1a\n"],
    "JPEG": [b"\xff\xd8\xff"],
    "ZIP": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    "EXE": [b"MZ"],
    "ELF": [b"\x7fELF"],
}

EXPECTED_SIGNATURES = {
    ".pdf": "PDF",
    ".png": "PNG",
    ".jpg": "JPEG",
    ".jpeg": "JPEG",
    ".zip": "ZIP",
    ".exe": "EXE",
    ".dll": "EXE",
}


def detect_signature(data: bytes):
    for file_type, signatures in FILE_SIGNATURES.items():
        for signature in signatures:
            if data.startswith(signature):
                return file_type

    return "UNKNOWN"


def analyze_file(filename: str, data: bytes):
    if not filename or not filename.strip():
        raise ValueError("Filename is required")

    if not data:
        raise ValueError("Empty files are not supported")

    if len(data) > MAX_FILE_SIZE:
        raise ValueError("Maximum file size is 10 MB")

    safe_filename = filename.replace("\\", "/").split("/")[-1]

    if safe_filename in {"", ".", ".."}:
        raise ValueError("Invalid filename")

    extension = Path(safe_filename).suffix.lower()

    file_size = len(data)

    sha256 = hashlib.sha256(data).hexdigest()

    signature = detect_signature(data)

    indicators = []
    risk_score = 0

    if extension in DANGEROUS_EXTENSIONS:
        risk_score += 45
        indicators.append(
            "File has a potentially executable extension"
        )

    elif extension in SUSPICIOUS_EXTENSIONS:
        risk_score += 25
        indicators.append(
            "File type can contain active or risky content"
        )

    parts = safe_filename.lower().split(".")

    if len(parts) >= 3:
        previous_extension = "." + parts[-2]

        if (
            previous_extension in DOUBLE_EXTENSION_TARGETS
            and extension in DANGEROUS_EXTENSIONS
        ):
            risk_score += 35
            indicators.append(
                "Potentially deceptive double file extension"
            )

    expected_signature = EXPECTED_SIGNATURES.get(extension)

    if (
        expected_signature
        and signature != "UNKNOWN"
        and signature != expected_signature
    ):
        risk_score += 30
        indicators.append(
            "File signature does not match its extension"
        )

    if signature == "EXE" and extension not in {".exe", ".dll"}:
        risk_score += 40
        indicators.append(
            "Executable-like file content detected"
        )

    if signature == "ELF":
        risk_score += 40
        indicators.append(
            "Linux executable signature detected"
        )

    risk_score = min(risk_score, 100)

    if risk_score >= 60:
        risk_level = "HIGH"
    elif risk_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    prediction = (
        "SUSPICIOUS"
        if risk_level in {"HIGH", "MEDIUM"}
        else "NO_INDICATORS_DETECTED"
    )

    explanation = (
        "This is a static heuristic file analysis. "
        "It checks file metadata, extension patterns, "
        "and basic file signatures without executing "
        "the uploaded content. It cannot confirm whether "
        "a file contains malware."
    )

    return {
        "status": "COMPLETED",
        "scan_type": "FILE",
        "filename": safe_filename,
        "file_size": file_size,
        "file_extension": extension or "NONE",
        "file_signature": signature,
        "sha256": sha256,
        "prediction": prediction,
        "risk_score": float(risk_score),
        "risk_level": risk_level,
        "indicators": indicators,
        "explanation": explanation,
        "model_version": "file-rules-1.0",
    }

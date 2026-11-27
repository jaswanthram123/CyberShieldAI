import os
from pathlib import Path
from typing import Literal

import joblib

import hmac
from fastapi import Request
from fastapi.responses import JSONResponse

from message_indicators import extract_message_indicators

from fastapi import FastAPI, HTTPException, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel, Field

from url_analyzer import analyze_url

from file_analyzer import MAX_FILE_SIZE
from advanced_file_analyzer import analyze_file_advanced

from gemini_explainer import explain_scan


# ======================================================
# 1. FastAPI Application
# ======================================================

app = FastAPI(
    title="CyberShield AI Engine",
    description=(
        "Local AI-powered cybersecurity analysis service "
        "with machine learning, static file inspection, "
        "YARA detection, and Ollama explanations"
    ),
    version="2.6.0"
)


# ==========================================
# Internal API Authentication
# ==========================================

INTERNAL_API_KEY = os.getenv(
    "AI_ENGINE_INTERNAL_KEY", ""
).strip()

if not INTERNAL_API_KEY:
    raise RuntimeError(
        "AI_ENGINE_INTERNAL_KEY is required"
    )


@app.middleware("http")
async def verify_internal_api_key(
    request: Request,
    call_next
):

    # Keep Render health checks accessible.
    if request.url.path in ("/", "/health"):
        return await call_next(request)

    provided_key = request.headers.get(
        "X-Internal-API-Key", ""
    )

    if not hmac.compare_digest(
        provided_key,
        INTERNAL_API_KEY
    ):
        return JSONResponse(
            status_code=401,
            content={
                "status": "ERROR",
                "message": "Unauthorized AI engine request"
            }
        )

    return await call_next(request)



# ======================================================
# 2. CORS Configuration
# ======================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


# ======================================================
# 3. Base Directory
# ======================================================

BASE_DIR = Path(__file__).resolve().parent


# ======================================================
# 4. Message ML Model Configuration
# ======================================================

MESSAGE_MODEL_VERSION = os.getenv(
    "MESSAGE_MODEL_VERSION",
    "v1"
).strip().lower()

MESSAGE_MODEL_FILES = {
    "v1": "scam_model.joblib",
    "v2": "scam_model_v2.joblib",
    "v3": "phishing_model_v3.joblib",
}

if MESSAGE_MODEL_VERSION not in MESSAGE_MODEL_FILES:
    raise RuntimeError(
        "MESSAGE_MODEL_VERSION must be v1, v2, or v3"
    )

MESSAGE_MODEL_PATH = (
    BASE_DIR / MESSAGE_MODEL_FILES[MESSAGE_MODEL_VERSION]
)

message_model = None

if MESSAGE_MODEL_PATH.exists():
    try:
        message_model = joblib.load(MESSAGE_MODEL_PATH)
        print(
            "[MESSAGE AI] Loaded:",
            MESSAGE_MODEL_PATH.name
        )
    except Exception as error:
        print(
            "[MESSAGE AI] Loading failed:",
            str(error)
        )
else:
    print(
        "[MESSAGE AI] Model file not found:",
        MESSAGE_MODEL_PATH.name
    )


# ======================================================
# 5. URL ML Model Configuration
# ======================================================

URL_MODEL_PATH = BASE_DIR / "url_model_v1.joblib"

url_model = None

if URL_MODEL_PATH.exists():
    try:
        url_model = joblib.load(URL_MODEL_PATH)
        print(
            "[URL AI] Loaded:",
            URL_MODEL_PATH.name
        )
    except Exception as error:
        print(
            "[URL AI] Loading failed:",
            str(error)
        )
else:
    print(
        "[URL AI] Model not found. "
        "Existing URL rules remain available."
    )


# ======================================================
# 6. Request Models
# ======================================================

class MessageRequest(BaseModel):
    message: str = Field(
        min_length=1,
        max_length=10000
    )


class URLAnalysisRequest(BaseModel):
    url: str = Field(
        min_length=1,
        max_length=2048
    )


class ExplanationRequest(BaseModel):

    scan_type: Literal[
        "MESSAGE",
        "URL",
        "FILE"
    ]

    risk_level: Literal[
        "LOW",
        "MEDIUM",
        "HIGH",
        "UNKNOWN"
    ]

    risk_score: float = Field(
        ge=0,
        le=100
    )

    prediction: str = Field(
        default="UNKNOWN",
        max_length=100
    )

    indicators: list[str] = Field(
        default_factory=list,
        max_length=10
    )


# ======================================================
# 7. Utility Functions
# ======================================================

def get_risk_level(score: float) -> str:

    if score >= 70:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


def get_message_model_name() -> str:

    versions = {
        "v1": "demo-1.0",
        "v2": "sms-spam-v2.0",
        "v3": "phishing-v3.0",
    }

    return versions[MESSAGE_MODEL_VERSION]


# ======================================================
# 8. Home Endpoint
# ======================================================

@app.get("/")
def home():

    return {
        "service": "CyberShield AI Engine",
        "status": "running",
        "version": "2.6.0",
        "message": (
            "Python FastAPI cybersecurity "
            "analysis service is running"
        )
    }


# ======================================================
# 9. Health Endpoint
# ======================================================

@app.get("/health")
def health():

    return {
        "status": (
            "UP"
            if message_model is not None
            else "DEGRADED"
        ),

        "service": "CyberShield AI Engine",

        "message_model_loaded": (
            message_model is not None
        ),

        # Preserve the original health field.
        "model_loaded": (
            message_model is not None
        ),

        "message_model_version": (
            MESSAGE_MODEL_VERSION
        ),

        "model_version": MESSAGE_MODEL_VERSION,

        "message_model_file": (
            MESSAGE_MODEL_PATH.name
        ),

        "model_file": MESSAGE_MODEL_PATH.name,

        "url_model_loaded": (
            url_model is not None
        ),

        "url_analyzer_available": True,

        "file_analyzer_available": True,

        "yara_enabled": True,

        "ollama_model": os.getenv(
            "OLLAMA_MODEL",
            "gemma3:1b"
        ),

        "ollama_integration_configured": True,
    }


# ======================================================
# 10. AI Message Analysis Endpoint
# ======================================================

@app.post("/analyze/message")
def analyze_message(request: MessageRequest):

    if message_model is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "Message ML model is unavailable. "
                "Check the configured model file."
            )
        )

    message = request.message.strip()

    if not message:
        raise HTTPException(
            status_code=422,
            detail="Message cannot be empty"
        )

    # ----------------------------------
    # Actual Machine Learning Inference
    # ----------------------------------

    try:
        probabilities = message_model.predict_proba(
            [message]
        )[0]

        classes = list(message_model.classes_)

        suspicious_index = classes.index(1)

        suspicious_probability = float(
            probabilities[suspicious_index]
        )

    except (AttributeError, ValueError, IndexError) as error:
        raise HTTPException(
            status_code=503,
            detail=(
                "Message model has an incompatible "
                "prediction interface"
            )
        ) from error

    risk_score = round(
        suspicious_probability * 100,
        2
    )

    prediction = (
        "SUSPICIOUS"
        if suspicious_probability >= 0.5
        else "LEGITIMATE"
    )

    confidence_score = round(
        float(max(probabilities)) * 100,
        2
    )

    risk_level = get_risk_level(risk_score)

    indicators = extract_message_indicators(message)

    # ----------------------------------
    # Version-Specific Explanation
    # ----------------------------------

    if MESSAGE_MODEL_VERSION == "v3":

        if prediction == "SUSPICIOUS":
            explanation = (
                "The phishing classification model "
                "identified text patterns associated "
                "with potential phishing. "
                "This is not confirmed evidence of fraud."
            )
        else:
            explanation = (
                "The phishing classification model "
                "identified patterns associated with "
                "non-phishing messages. "
                "This does not guarantee safety."
            )

    elif MESSAGE_MODEL_VERSION == "v2":

        if prediction == "SUSPICIOUS":
            explanation = (
                "The SMS spam classification model "
                "identified patterns associated "
                "with spam messages. "
                "Spam classification does not "
                "confirm phishing."
            )
        else:
            explanation = (
                "The SMS spam classification model "
                "identified patterns associated "
                "with legitimate messages. "
                "This does not guarantee safety."
            )

    else:

        if prediction == "SUSPICIOUS":
            explanation = (
                "The demonstration model identified "
                "text patterns associated "
                "with suspicious messages."
            )
        else:
            explanation = (
                "The demonstration model identified "
                "text patterns associated "
                "with legitimate messages."
            )

    
    return {
        "status": "COMPLETED",
        "scan_type": "MESSAGE",

        "prediction": prediction,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "confidence_score": confidence_score,

        "explanation": explanation,
        "model_version": get_message_model_name(),

        # Actual detected message indicators
        "indicators": indicators,
        "indicator_count": len(indicators),
    }



# ======================================================
# 11. AI URL Analysis Endpoint
# ======================================================


@app.post("/analyze/url")
def analyze_url_endpoint(request: URLAnalysisRequest):

    try:
        # ----------------------------------
        # Step 1: Rule-Based URL Analysis
        # ----------------------------------

        result = analyze_url(request.url)

        # Continue using rule-based analysis
        # if the trained ML model is unavailable.
        if url_model is None:
            return result

        url = request.url.strip()

        # ----------------------------------
        # Step 2: Machine Learning Analysis
        # ----------------------------------

        try:
            probabilities = url_model.predict_proba(
                [url]
            )[0]

            classes = list(url_model.classes_)

            # Class 1 represents phishing.
            phishing_index = classes.index(1)

            phishing_probability = float(
                probabilities[phishing_index]
            )

            if not (
                0.0 <= phishing_probability <= 1.0
            ):
                raise ValueError(
                    "Invalid ML probability"
                )

        except (
            AttributeError,
            ValueError,
            IndexError,
            TypeError
        ) as error:

            raise HTTPException(
                status_code=503,
                detail="URL ML model is incompatible"
            ) from error

        # ----------------------------------
        # Step 3: Calculate Scores
        # ----------------------------------

        ml_score = round(
            phishing_probability * 100,
            2
        )

        heuristic_score = float(
            result.get("risk_score", 0)
        )

        # Experimental equal-weighted score.
        combined_score = round(
            (heuristic_score + ml_score) / 2,
            2
        )

        # ----------------------------------
        # Step 4: Final Risk Classification
        # ----------------------------------

        risk_level = get_risk_level(
            combined_score
        )

        # Final prediction must agree with
        # the combined risk classification.
        if risk_level in {"HIGH", "MEDIUM"}:
            prediction = "SUSPICIOUS"
        else:
            prediction = "NO_INDICATORS_DETECTED"

        # Keep the ML model's independent
        # prediction visible for comparison.
        ml_prediction = (
            "SUSPICIOUS"
            if phishing_probability >= 0.5
            else "LEGITIMATE"
        )

        # ----------------------------------
        # Step 5: Preserve Existing Fields
        # ----------------------------------

        old_explanation = str(
            result.get("explanation", "")
        )

        result["heuristic_risk_score"] = (
            heuristic_score
        )

        result["ml_risk_score"] = (
            ml_score
        )

        result["ml_prediction"] = (
            ml_prediction
        )

        result["risk_score"] = (
            combined_score
        )

        result["risk_level"] = (
            risk_level
        )

        result["prediction"] = (
            prediction
        )

        result["model_version"] = (
            "url-ml-v1.0"
        )

        # ----------------------------------
        # Step 6: Explanation
        # ----------------------------------

        result["explanation"] = (
            old_explanation
            + " Machine learning phishing-class "
            "score: "
            + str(ml_score)
            + "%. Heuristic risk score: "
            + str(round(heuristic_score, 2))
            + "%. The final risk score is the "
            "experimental equal-weighted average "
            "of both scores. "
            "The final prediction follows the "
            "combined risk level, while the ML "
            "prediction is displayed separately. "
            "These scores are not calibrated "
            "probabilities of malicious activity."
        )

        return result

    except HTTPException:
        raise

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        ) from error

# ======================================================
# 12. Advanced File Analysis Endpoint
# ======================================================

@app.post("/analyze/file")
async def analyze_file_endpoint(
    file: UploadFile = File(...)
):

    try:
        if not file.filename:
            raise HTTPException(
                status_code=400,
                detail="Filename is required"
            )

        # Read at most 10 MB + 1 byte.
        data = await file.read(
            MAX_FILE_SIZE + 1
        )

        if len(data) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail="Maximum file size is 10 MB"
            )

        if len(data) == 0:
            raise HTTPException(
                status_code=400,
                detail="Empty files are not supported"
            )

        # ----------------------------------
        # Basic + Advanced + YARA Analysis
        # ----------------------------------

        try:
            result = analyze_file_advanced(
                file.filename,
                data
            )

        except ValueError as error:
            raise HTTPException(
                status_code=400,
                detail=str(error)
            ) from error

        return result

    finally:
        await file.close()


# ======================================================
# 13. Ollama AI Explanation Endpoint
# ======================================================

@app.post("/explain")
def explain_security_result(
    request: ExplanationRequest
):

    scan = request.model_dump()

    # Only bounded, structured findings
    # are forwarded to Ollama.
    #
    # Uploaded file bytes and original
    # message contents are not forwarded.

    scan["indicators"] = [
        indicator[:200]
        for indicator in scan["indicators"]
    ]

    result = explain_scan(scan)

    if result.get("status") != "COMPLETED":
        raise HTTPException(
            status_code=503,
            detail=result.get(
                "error",
                "Local Ollama explanation unavailable"
            )
        )

    return result


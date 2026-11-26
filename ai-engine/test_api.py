
import pytest
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_home():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "running"


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["service"] == "CyberShield AI Engine"


def test_health_model_status():
    response = client.get("/health")
    data = response.json()

    assert data["status"] in ["UP", "DEGRADED"]
    assert isinstance(data["message_model_loaded"], bool)


def test_empty_message():
    response = client.post(
        "/analyze/message",
        json={"message": ""}
    )

    assert response.status_code in [422, 503]


def test_missing_file():
    response = client.post("/analyze/file")

    assert response.status_code == 422


def test_missing_explanation_body():
    response = client.post("/explain")

    assert response.status_code == 422



def test_message_analysis():
    response = client.post(
        "/analyze/message",
        json={
            "message": "Your account is locked. Verify your password immediately."
        }
    )

    if response.status_code == 503:
        pytest.skip("Message ML model is unavailable")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "COMPLETED"
    assert data["scan_type"] == "MESSAGE"
    assert data["prediction"] in ["SUSPICIOUS", "LEGITIMATE"]
    assert 0 <= data["risk_score"] <= 100
    assert 0 <= data["confidence_score"] <= 100
    assert isinstance(data["indicators"], list)
    assert data["indicator_count"] == len(data["indicators"])


def test_url_analysis():
    response = client.post(
        "/analyze/url",
        json={"url": "https://example.com"}
    )

    assert response.status_code == 200

    data = response.json()

    assert data["prediction"] in [
    "SUSPICIOUS",
    "LEGITIMATE",
    "NO_INDICATORS_DETECTED",
]
    assert 0 <= data["risk_score"] <= 100
    assert isinstance(data["explanation"], str)


def test_missing_message():
    response = client.post(
        "/analyze/message",
        json={}
    )

    assert response.status_code == 422


def test_message_exceeds_max_length():
    response = client.post(
        "/analyze/message",
        json={"message": "A" * 10001}
    )

    assert response.status_code == 422


def test_missing_url():
    response = client.post(
        "/analyze/url",
        json={}
    )

    assert response.status_code == 422


def test_url_exceeds_max_length():
    response = client.post(
        "/analyze/url",
        json={"url": "a" * 2049}
    )

    assert response.status_code == 422



def test_empty_file_upload():
    response = client.post(
        "/analyze/file",
        files={
            "file": ("empty.txt", b"", "text/plain")
        }
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Empty files are not supported"
    )


def test_file_exceeds_size_limit():
    response = client.post(
        "/analyze/file",
        files={
            "file": (
                "large.txt",
                b"A" * (10 * 1024 * 1024 + 1),
                "text/plain"
            )
        }
    )

    assert response.status_code == 413
    assert response.json()["detail"] == (
        "Maximum file size is 10 MB"
    )


def test_valid_file_upload():
    response = client.post(
        "/analyze/file",
        files={
            "file": (
                "sample.txt",
                b"CyberShield AI test file",
                "text/plain"
            )
        }
    )

    assert response.status_code == 200
    assert isinstance(response.json(), dict)

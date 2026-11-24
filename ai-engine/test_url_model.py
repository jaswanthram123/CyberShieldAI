
from pathlib import Path
import joblib

BASE = Path(__file__).resolve().parent

model = joblib.load(
    BASE / "url_model_v1.joblib"
)

urls = [
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://github.com",
    "http://192.168.1.10/verify-password",
    "http://example.com/account-verification",
    "https://example.com/login",
]

probabilities = model.predict_proba(urls)

phishing_index = list(model.classes_).index(1)

for url, prob in zip(urls, probabilities):
    score = float(prob[phishing_index]) * 100

    prediction = (
        "SUSPICIOUS" if score >= 50
        else "LEGITIMATE"
    )

    print("\nURL:", url)
    print("Prediction:", prediction)
    print("ML Phishing Score:", round(score, 2), "%")

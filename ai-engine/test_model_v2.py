
from pathlib import Path
import joblib

MODEL_PATH = (
    Path(__file__).resolve().parent
    / "scam_model_v2.joblib"
)

model = joblib.load(MODEL_PATH)

messages = [
    "Hi, let's meet tomorrow at 10 AM.",
    "Please send the project report today.",
    "Your bank account is blocked. Verify your password.",
    "Congratulations! You won a cash prize.",
    "Your OTP is 458921. Never share it with anyone.",
    "You must pay a registration fee to receive your job offer.",
]

probabilities = model.predict_proba(messages)
predictions = model.predict(messages)

spam_index = list(model.classes_).index(1)

for message, prediction, probs in zip(
    messages,
    predictions,
    probabilities,
):
    spam_score = probs[spam_index] * 100

    print("\nMessage:", message)

    print(
        "Prediction:",
        "SPAM" if prediction == 1 else "LEGITIMATE",
    )

    print("Spam score:", round(spam_score, 2), "%")

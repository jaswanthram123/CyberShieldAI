
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

messages = [
    "Congratulations you won a cash prize claim now",
    "Your bank account is blocked verify your password immediately",
    "You have won a lottery send money to receive your reward",
    "Urgent update your KYC using this suspicious link",
    "Your package is held pay a small fee to release it",
    "You are selected for a job pay registration fees today",
    "Click this link to claim your free gift",
    "Your account will be suspended share your OTP now",
    "Earn guaranteed money daily with no investment",
    "You won a smartphone submit your card details",
    "Hi are we meeting tomorrow morning",
    "Please send the project report by evening",
    "Your interview is scheduled for Monday at 10 AM",
    "Can you review the code changes today",
    "Your order has been delivered successfully",
    "Let's have lunch together tomorrow",
    "The team meeting starts at 3 PM",
    "Please check the updated project documentation",
    "Thank you for attending the interview",
    "Your appointment has been confirmed",
]

labels = [1] * 10 + [0] * 10

model = Pipeline([
    ("tfidf", TfidfVectorizer(ngram_range=(1, 2))),
    ("classifier", LogisticRegression(max_iter=1000))
])

model.fit(messages, labels)

model_path = Path(__file__).resolve().parent / "scam_model.joblib"

joblib.dump(model, model_path)

print("Model trained successfully")
print(f"Model saved to: {model_path}")

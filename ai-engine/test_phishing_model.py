
import joblib

model = joblib.load("phishing_model_v3.joblib")

messages = [
    "Hello hi, how are you?",
    "Good morning!",
    "Can we meet tomorrow?",
    "Thank you for your help.",
    "What are you doing?",
    "Happy birthday!",
    "Your account has been suspended. Click here to verify your password.",
    "URGENT! Your bank account will be blocked. Enter your OTP immediately.",
    "You won a cash prize! Claim your reward using this link.",
    "Please send me your password to restore access.",
]

print("Model classes:", model.classes_)
print()

for message in messages:
    probabilities = model.predict_proba([message])[0]

    scores = {
        str(label): round(float(prob) * 100, 2)
        for label, prob in zip(model.classes_, probabilities)
    }

    print("Message:", message)
    print("Prediction:", model.predict([message])[0])
    print("Class probabilities:", scores)
    print("-" * 55)

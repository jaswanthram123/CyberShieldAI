
import joblib

model = joblib.load("phishing_model_v3.joblib")

vectorizer = model.named_steps["tfidf"]
classifier = model.named_steps["classifier"]

messages = [
    "Hello hi, how are you?",
    "Good morning!",
    "Thank you for your help.",
    "Can we meet tomorrow?",
    "Your bank account is blocked. Verify your OTP.",
]

print("Model classes:", classifier.classes_)
print("Vocabulary size:", len(vectorizer.vocabulary_))
print("Model intercept:", classifier.intercept_)
print("-" * 60)

for message in messages:

    features = vectorizer.transform([message])
    probabilities = model.predict_proba([message])[0]

    phishing_index = list(model.classes_).index(1)
    phishing_score = probabilities[phishing_index] * 100

    feature_names = vectorizer.get_feature_names_out()

    matched_features = [
        feature_names[index]
        for index in features.indices
    ]

    print("\nMessage:", message)
    print("Matched features:", matched_features)
    print("Nonzero features:", features.nnz)
    print(f"Phishing score: {phishing_score:.2f}%")
    print("-" * 60)

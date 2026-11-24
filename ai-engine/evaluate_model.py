
from pathlib import Path

import joblib
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

MODEL_PATH = (
    Path(__file__).resolve().parent
    / "scam_model.joblib"
)

model = joblib.load(MODEL_PATH)

# Independent examples not copied directly
# from the existing training dataset.
test_messages = [
    "Your banking access has expired. Confirm your login credentials now.",
    "We noticed unusual activity. Enter your OTP to restore access.",
    "Claim your exclusive reward by providing your card information.",
    "Your delivery is waiting. Pay a verification charge using this link.",
    "You have been shortlisted. Deposit a processing fee to continue.",
    "Your email will be disabled unless you verify your password.",
    "Congratulations, you qualify for an instant cash reward.",
    "Your payment failed. Update your billing information immediately.",
    "The team has postponed today's meeting to Friday.",
    "Please review the latest version of the project proposal.",
    "Your appointment is confirmed for next Wednesday.",
    "I uploaded the documentation to our shared folder.",
    "The interview panel will join the call at 11 AM.",
    "Can you help me debug the login endpoint?",
    "Thank you for sending the updated report.",
    "Your parcel arrived at the reception desk.",
]

# 1 = suspicious, 0 = legitimate
test_labels = [1] * 8 + [0] * 8

predictions = model.predict(test_messages)

print("\nMODEL EVALUATION")
print("------------------------------")

print(
    "Accuracy:",
    round(
        accuracy_score(test_labels, predictions) * 100,
        2,
    ),
    "%",
)

print("\nClassification Report:")

print(
    classification_report(
        test_labels,
        predictions,
        labels=[0, 1],
        target_names=["Legitimate", "Suspicious"],
        zero_division=0,
    )
)

print("Confusion Matrix:")

print(
    confusion_matrix(
        test_labels,
        predictions,
        labels=[0, 1],
    )
)

print("\nIndividual Predictions:")

for message, actual, predicted in zip(
    test_messages,
    test_labels,
    predictions,
):
    print(
        f"Actual: {actual} | "
        f"Predicted: {predicted} | "
        f"{message}"
    )

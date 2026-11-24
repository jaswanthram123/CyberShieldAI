"""Train an experimental v4 phishing classifier using email data and legitimate SMS.

Keeps phishing_model_v3.joblib unchanged. Only UCI SMS `ham` messages are
used, because the UCI `spam` category is not equivalent to phishing.
"""

import io
import json
import re
import urllib.request
import zipfile
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

BASE = Path(__file__).resolve().parent
DATA_DIR = BASE / "data"
EMAIL_PATH = DATA_DIR / "phishing_messages.csv"
SMS_PATH = DATA_DIR / "SMSSpamCollection"
MODEL_PATH = BASE / "phishing_model_v4.joblib"
METRICS_PATH = BASE / "phishing_model_v4_metrics.json"
UCI_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"

# These known diagnostic cases are excluded from training by exact normalized
# text matching. They are only a small smoke test, NOT representative accuracy.
SMOKE_TESTS = [
    ("Hello hi, how are you?", 0),
    ("Good morning!", 0),
    ("Can we meet tomorrow?", 0),
    ("Thank you for your help.", 0),
    ("What are you doing?", 0),
    ("Happy birthday!", 0),
    ("Your account has been suspended. Click here to verify your password.", 1),
    ("URGENT! Your bank account will be blocked. Enter your OTP immediately.", 1),
    ("You won a cash prize! Claim your reward using this link.", 1),
    ("Please send me your password to restore access.", 1),
]


def normalize_key(value):
    return re.sub(r"\s+", " ", str(value).strip()).casefold()


def load_email_data():
    if not EMAIL_PATH.exists():
        raise FileNotFoundError(
            f"Missing {EMAIL_PATH}. Run prepare_phishing_dataset.py first."
        )
    df = pd.read_csv(EMAIL_PATH, usecols=["text", "label"])
    df = df.dropna(subset=["text", "label"]).copy()
    df["text"] = df["text"].astype(str).str.strip()
    df["label"] = df["label"].astype(int)
    df = df[(df["text"] != "") & df["label"].isin([0, 1])].copy()
    df["key"] = df["text"].map(normalize_key)

    # Drop duplicated or conflicting normalized texts before splitting.
    conflicts = df.groupby("key")["label"].nunique()
    conflict_keys = set(conflicts[conflicts > 1].index)
    df = df[~df["key"].isin(conflict_keys)]
    return df.drop_duplicates("key").reset_index(drop=True)


def load_legitimate_sms():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not SMS_PATH.exists():
        print("Downloading UCI SMS Spam Collection...")
        with urllib.request.urlopen(UCI_URL, timeout=45) as response:
            archive_bytes = response.read()
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
            # Read only the expected file, not an arbitrary archive path.
            matches = [n for n in zf.namelist() if n.rsplit("/", 1)[-1] == "SMSSpamCollection"]
            if len(matches) != 1:
                raise RuntimeError("UCI archive missing SMSSpamCollection")
            SMS_PATH.write_bytes(zf.read(matches[0]))

    rows = []
    for line in SMS_PATH.read_text(encoding="latin-1").splitlines():
        label, separator, text = line.partition("\t")
        if separator and label == "ham" and text.strip():
            rows.append({"text": text.strip(), "label": 0})
    if len(rows) < 1000:
        raise ValueError("Unexpectedly few UCI legitimate SMS messages")
    df = pd.DataFrame(rows)
    df["key"] = df["text"].map(normalize_key)
    return df.drop_duplicates("key").reset_index(drop=True)


def evaluate(name, labels, predicted):
    matrix = confusion_matrix(labels, predicted, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()
    output = {
        "count": int(len(labels)),
        "accuracy": float(accuracy_score(labels, predicted)),
        "confusion_matrix": matrix.tolist(),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else None,
        "precision": float(precision_score(labels, predicted, zero_division=0)),
        "recall": float(recall_score(labels, predicted, zero_division=0)),
        "f1": float(f1_score(labels, predicted, zero_division=0)),
    }
    print(f"\n{name}:")
    print(json.dumps(output, indent=2))
    return output


def main():
    email = load_email_data()
    sms = load_legitimate_sms()

    # Exclude familiar diagnostic examples from both training and evaluation.
    smoke_keys = {normalize_key(text) for text, _ in SMOKE_TESTS}
    email = email[~email["key"].isin(smoke_keys)].copy()
    sms = sms[~sms["key"].isin(smoke_keys)].copy()

    # Prevent exact text leakage between the email and SMS sources.
    sms = sms[~sms["key"].isin(set(email["key"]))].copy()
    if email["label"].nunique() != 2:
        raise ValueError("Email dataset must have both legitimate and phishing samples")

    email_train, email_test = train_test_split(
        email, test_size=0.2, random_state=42, stratify=email["label"]
    )
    sms_train, sms_test = train_test_split(
        sms, test_size=0.2, random_state=42
    )

    train = pd.concat([email_train, sms_train], ignore_index=True)
    train = train.sample(frac=1, random_state=42).reset_index(drop=True)
    print("Training email examples:", len(email_train))
    print("Training legitimate SMS examples:", len(sms_train))
    print("Held-out email examples:", len(email_test))
    print("Held-out legitimate SMS examples:", len(sms_test))
    print("Training labels:", train["label"].value_counts().to_dict())

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2), max_features=40000,
            min_df=2, sublinear_tf=True,
        )),
        ("classifier", LogisticRegression(
            max_iter=2000, random_state=42,
        )),
    ])
    pipeline.fit(train["text"], train["label"])

    email_metrics = evaluate(
        "Held-out phishing email test", email_test["label"],
        pipeline.predict(email_test["text"])
    )
    sms_metrics = evaluate(
        "Held-out legitimate SMS test", sms_test["label"],
        pipeline.predict(sms_test["text"])
    )

    print("\nDiagnostic messages (not in training):")
    phishing_index = list(pipeline.classes_).index(1)
    failures = 0
    for text, expected in SMOKE_TESTS:
        predicted = int(pipeline.predict([text])[0])
        probability = 100 * float(pipeline.predict_proba([text])[0][phishing_index])
        passed = predicted == expected
        failures += int(not passed)
        print(f"{'PASS' if passed else 'FAIL'} | {probability:6.2f}% | expected={expected}, got={predicted} | {text}")

    metrics = {
        "model_version": "phishing-v4.0-experimental",
        "training_data": "Phishing email dataset + UCI SMS Collection legitimate (ham) messages",
        "train_count": int(len(train)),
        "email_test": email_metrics,
        "legitimate_sms_test": sms_metrics,
        "diagnostic_failures": int(failures),
        "warning": "SMS spam is not phishing; no spam samples were relabeled as phishing. Scores are not calibrated probabilities.",
    }

    # Save separately. Do not change the active v3 deployment automatically.
    joblib.dump(pipeline, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print("\nExperimental v4 saved:", MODEL_PATH)
    print("Metrics saved:", METRICS_PATH)
    print("Do NOT switch the API to v4 until these results are reviewed.")


if __name__ == "__main__":
    main()


from pathlib import Path
import json

import joblib
import pandas as pd

from sklearn.model_selection import (
    train_test_split,
    StratifiedKFold,
    cross_val_score,
)
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)

BASE = Path(__file__).resolve().parent
DATA = BASE / "data" / "phishing_messages.csv"
MODEL = BASE / "phishing_model_v3.joblib"
METRICS = BASE / "phishing_model_v3_metrics.json"

# Load data
df = pd.read_csv(DATA)
df = df.dropna(subset=["text", "label"])
df = df.drop_duplicates(subset=["text"])

X = df["text"].astype(str)
y = df["label"].astype(int)

# Keep test messages separate from training
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.20,
    stratify=y,
    random_state=42,
)

# Phishing detection pipeline
pipeline = Pipeline([
    ("tfidf", TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=30000,
        min_df=2,
        sublinear_tf=True,
    )),
    ("classifier", LogisticRegression(
        max_iter=2000,
        class_weight="balanced",
        random_state=42,
    )),
])

# Cross-validation only on training data
cv = StratifiedKFold(
    n_splits=5,
    shuffle=True,
    random_state=42,
)

cv_scores = cross_val_score(
    pipeline,
    X_train,
    y_train,
    cv=cv,
    scoring="f1",
    n_jobs=-1,
)

print("Cross-validation F1:", cv_scores.mean())

# Fit on training partition
pipeline.fit(X_train, y_train)

# Evaluate unseen test partition
predictions = pipeline.predict(X_test)

metrics = {
    "model_version": "phishing-v3.0",
    "dataset": "Balanced Phishing Email Detection Subset",
    "train_count": len(X_train),
    "test_count": len(X_test),
    "accuracy": accuracy_score(y_test, predictions),
    "precision": precision_score(
        y_test, predictions, zero_division=0
    ),
    "recall": recall_score(
        y_test, predictions, zero_division=0
    ),
    "f1": f1_score(
        y_test, predictions, zero_division=0
    ),
    "cv_f1": float(cv_scores.mean()),
    "confusion_matrix": confusion_matrix(
        y_test, predictions, labels=[0, 1]
    ).tolist(),
}

print("\nPHISHING MODEL V3 RESULTS")
print("---------------------------")

for key, value in metrics.items():
    print(f"{key}: {value}")

print("\nClassification Report:")
print(classification_report(
    y_test,
    predictions,
    labels=[0, 1],
    target_names=["Safe", "Phishing"],
    zero_division=0,
))

# Save independently; existing models are preserved
joblib.dump(pipeline, MODEL)

METRICS.write_text(
    json.dumps(metrics, indent=4),
    encoding="utf-8",
)

print("\nModel saved:", MODEL)
print("Metrics saved:", METRICS)

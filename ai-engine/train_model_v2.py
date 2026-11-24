
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

BASE_DIR = Path(__file__).resolve().parent

DATA_PATH = BASE_DIR / "data" / "messages_v2.csv"
MODEL_PATH = BASE_DIR / "scam_model_v2.joblib"
REPORT_PATH = BASE_DIR / "model_v2_metrics.json"

# -------------------------------------
# 1. Load dataset
# -------------------------------------

df = pd.read_csv(DATA_PATH)

df = df.dropna(subset=["message", "label"])
df = df.drop_duplicates(subset=["message"])

X = df["message"].astype(str)
y = df["label"].astype(int)

if set(y.unique()) != {0, 1}:
    raise ValueError("Dataset must contain both labels 0 and 1.")

print("Total messages:", len(df))
print("Legitimate:", (y == 0).sum())
print("Spam:", (y == 1).sum())

# -------------------------------------
# 2. Split training and testing data
# -------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))

# -------------------------------------
# 3. Create ML pipeline
# -------------------------------------

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            ngram_range=(1, 2),
            min_df=2,
            max_features=30000,
            sublinear_tf=True,
        ),
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=42,
        ),
    ),
])

# -------------------------------------
# 4. Cross-validation
# -------------------------------------

cv = StratifiedKFold(
    n_splits=5,
    shuffle=True,
    random_state=42,
)

cv_scores = cross_val_score(
    model,
    X_train,
    y_train,
    cv=cv,
    scoring="f1",
    n_jobs=-1,
)

print("\nCross-validation F1 scores:")
print(cv_scores)

print(
    "Average CV F1:",
    round(cv_scores.mean(), 4),
)

# -------------------------------------
# 5. Train final model
# -------------------------------------

model.fit(X_train, y_train)

# -------------------------------------
# 6. Evaluate on held-out test data
# -------------------------------------

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)
precision = precision_score(y_test, predictions, zero_division=0)
recall = recall_score(y_test, predictions, zero_division=0)
f1 = f1_score(y_test, predictions, zero_division=0)

print("\nMODEL V2 EVALUATION")
print("-----------------------------")
print("Accuracy:", round(accuracy * 100, 2), "%")
print("Precision:", round(precision * 100, 2), "%")
print("Recall:", round(recall * 100, 2), "%")
print("F1 Score:", round(f1 * 100, 2), "%")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Legitimate", "Spam"],
        zero_division=0,
    )
)

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions, labels=[0, 1]))

# -------------------------------------
# 7. Save model and evaluation metrics
# -------------------------------------

joblib.dump(model, MODEL_PATH)

metrics = {
    "model_version": "sms-spam-v2.0",
    "dataset": "UCI SMS Spam Collection",
    "training_samples": len(X_train),
    "testing_samples": len(X_test),
    "accuracy": float(accuracy),
    "precision": float(precision),
    "recall": float(recall),
    "f1_score": float(f1),
    "cv_f1_mean": float(cv_scores.mean()),
}

REPORT_PATH.write_text(
    json.dumps(metrics, indent=4),
    encoding="utf-8",
)

print("\nModel saved successfully.")
print("Model:", MODEL_PATH)
print("Metrics:", REPORT_PATH)

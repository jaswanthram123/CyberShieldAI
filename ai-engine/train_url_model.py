
from pathlib import Path
from urllib.parse import urlsplit
import json
import joblib
import pandas as pd

from sklearn.model_selection import GroupShuffleSplit
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

DATA = BASE / "data" / "phishing_urls.csv"
MODEL = BASE / "url_model_v1.joblib"
METRICS = BASE / "url_model_v1_metrics.json"

df = pd.read_csv(DATA)
df = df.dropna(subset=["url", "label"])
df["url"] = df["url"].astype(str).str.strip()
df = df[df["url"] != ""]
df = df.drop_duplicates(subset=["url"])

def hostname(url):
    try:
        text = url if "://" in url else "http://" + url
        return urlsplit(text).hostname or url
    except ValueError:
        return url

# Group related URLs by hostname so that the
# same hostname is not present in both sets.
df["host"] = df["url"].map(hostname)

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42,
)

train_idx, test_idx = next(
    splitter.split(
        df["url"],
        df["label"],
        groups=df["host"],
    )
)

train = df.iloc[train_idx]
test = df.iloc[test_idx]

if train["label"].nunique() != 2 or test["label"].nunique() != 2:
    raise RuntimeError(
        "Both training and testing sets must contain "
        "legitimate and phishing URLs."
    )

print("Training URLs:", len(train))
print("Testing URLs:", len(test))

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            max_features=30000,
            sublinear_tf=True,
            lowercase=True,
        ),
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42,
        ),
    ),
])

model.fit(train["url"], train["label"])

predictions = model.predict(test["url"])

metrics = {
    "model_version": "url-ml-v1.0",
    "training_count": int(len(train)),
    "testing_count": int(len(test)),
    "accuracy": float(
        accuracy_score(test["label"], predictions)
    ),
    "precision": float(
        precision_score(
            test["label"], predictions, zero_division=0
        )
    ),
    "recall": float(
        recall_score(
            test["label"], predictions, zero_division=0
        )
    ),
    "f1": float(
        f1_score(
            test["label"], predictions, zero_division=0
        )
    ),
    "confusion_matrix": confusion_matrix(
        test["label"],
        predictions,
        labels=[0, 1],
    ).tolist(),
}

print("\nURL MODEL EVALUATION")
print("-------------------------")

for key, value in metrics.items():
    print(key, ":", value)

print("\nClassification Report:")
print(
    classification_report(
        test["label"],
        predictions,
        labels=[0, 1],
        target_names=["Legitimate", "Phishing"],
        zero_division=0,
    )
)

joblib.dump(model, MODEL)

METRICS.write_text(
    json.dumps(metrics, indent=4),
    encoding="utf-8",
)

print("\nModel saved:", MODEL)
print("Metrics saved:", METRICS)

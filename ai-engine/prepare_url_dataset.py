
from pathlib import Path
from urllib.parse import urlsplit
import pandas as pd
from ucimlrepo import fetch_ucirepo

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

OUTPUT = DATA_DIR / "phishing_urls.csv"

print("Downloading PhiUSIIL dataset...")

dataset = fetch_ucirepo(id=967)

features = dataset.data.features
targets = dataset.data.targets

df = pd.DataFrame({
    "url": features["URL"].astype(str),
    "source_label": targets.iloc[:, 0].astype(int),
})

# UCI source:
# 0 = phishing
# 1 = legitimate
#
# Our model:
# 1 = phishing
# 0 = legitimate

df["label"] = (df["source_label"] == 0).astype(int)

df["url"] = df["url"].str.strip()
df = df[df["url"] != ""].copy()

# Remove contradictory labels
conflicts = df.groupby("url")["label"].nunique()
conflicting_urls = conflicts[conflicts > 1].index
df = df[~df["url"].isin(conflicting_urls)]

df = df.drop_duplicates(subset=["url"])

# Keep a manageable sample for local training
max_per_class = 25000

parts = []

for label in [0, 1]:
    part = df[df["label"] == label]

    if len(part) > max_per_class:
        part = part.sample(
            n=max_per_class,
            random_state=42,
        )

    parts.append(part)

df = pd.concat(parts, ignore_index=True)

df = df[["url", "label"]]

df.to_csv(OUTPUT, index=False)

print("Dataset prepared successfully.")
print("Total URLs:", len(df))
print("Legitimate:", (df["label"] == 0).sum())
print("Phishing:", (df["label"] == 1).sum())
print("Saved to:", OUTPUT)

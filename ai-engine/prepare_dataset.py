
from pathlib import Path
from urllib.request import urlretrieve
from zipfile import ZipFile
import csv
import io

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

ZIP_PATH = DATA_DIR / "sms_spam.zip"
CSV_PATH = DATA_DIR / "messages_v2.csv"

URL = (
    "https://archive.ics.uci.edu/static/public/"
    "228/sms+spam+collection.zip"
)

if not ZIP_PATH.exists():
    print("Downloading UCI SMS Spam Collection...")
    urlretrieve(URL, ZIP_PATH)

with ZipFile(ZIP_PATH) as archive:
    with archive.open("SMSSpamCollection") as file:
        content = file.read()

df = pd.read_csv(
    io.BytesIO(content),
    sep="\t",
    header=None,
    names=["category", "message"],
    encoding="utf-8",
    encoding_errors="replace",
    quoting=csv.QUOTE_NONE,
)

df["category"] = df["category"].str.strip().str.lower()

df = df[df["category"].isin(["ham", "spam"])].copy()
df = df.dropna(subset=["message"])
df["message"] = df["message"].astype(str).str.strip()
df = df[df["message"] != ""]

df["label"] = df["category"].map({
    "ham": 0,
    "spam": 1,
})

df = df.drop_duplicates(subset=["message"])
df = df[["message", "label"]]

df.to_csv(CSV_PATH, index=False, encoding="utf-8")

print("Dataset prepared successfully.")
print("Total messages:", len(df))
print("Legitimate:", (df["label"] == 0).sum())
print("Spam:", (df["label"] == 1).sum())
print("Saved to:", CSV_PATH)


from pathlib import Path
import pandas as pd
from huggingface_hub import hf_hub_download

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

print("Downloading phishing email dataset...")

file_path = hf_hub_download(
    repo_id="jhonrayo99/phishing-email-balanced-6000",
    filename="phishing_email_subset.csv",
    repo_type="dataset",
)

df = pd.read_csv(file_path)

# Keep the required columns
df = df[["text", "label"]].copy()

df = df.dropna(subset=["text", "label"])
df["text"] = df["text"].astype(str).str.strip()
df["label"] = df["label"].astype(int)

df = df[df["text"] != ""]
df = df[df["label"].isin([0, 1])]

# Remove conflicting labels for identical text
df = df.drop_duplicates(subset=["text", "label"])

conflicts = df.groupby("text")["label"].nunique()
conflicting_texts = conflicts[conflicts > 1].index

df = df[~df["text"].isin(conflicting_texts)]
df = df.drop_duplicates(subset=["text"])

output = DATA_DIR / "phishing_messages.csv"

df.to_csv(output, index=False)

print("Dataset ready.")
print("Total:", len(df))
print("Safe:", (df["label"] == 0).sum())
print("Phishing:", (df["label"] == 1).sum())
print("Saved:", output)

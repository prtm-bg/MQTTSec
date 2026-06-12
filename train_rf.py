# train_rf.py
# Requires: MQTT_dataset.csv from https://www.kaggle.com/datasets/cnrieiit/mqttset
#
# Usage:
#   pip install pandas scikit-learn numpy
#   python3 train_rf.py
#
# Output: rf_model.pkl  (copy this to RPi 5 alongside mqttsec_broker.py)

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pickle
import os

# ── 1. Load and filter dataset ─────────────────────────────────────────────
CSV_PATH = "train70.csv"   # adjust if your filename differs

if not os.path.exists(CSV_PATH):
    raise FileNotFoundError(
        f"Dataset not found: {CSV_PATH}\n"
        "Download from https://www.kaggle.com/datasets/cnrieiit/mqttset\n"
        "The file is usually named 'train70.csv' or similar. "
        "Rename it to MQTT_dataset.csv or change CSV_PATH above."
    )

print(f"[1] Loading dataset from {CSV_PATH} ...")
df = pd.read_csv(CSV_PATH)
print(f"    Total rows: {len(df)}")
print(f"    Columns: {df.columns.tolist()}")
print(f"    Class distribution:\n{df['target'].value_counts()}\n")

# Keep only legitimate and dos traffic — same as paper Section 6.1
df = df[df['target'].isin(['legitimate', 'dos'])].copy()
print(f"[2] After filtering legitimate/dos: {len(df)} rows")

# ── 2. Feature selection ───────────────────────────────────────────────────
# Paper Section 5.2 and Figure 8: mqtt.len and tcp.time_delta are the
# two most correlated features with the target.
FEATURES = ['mqtt.len', 'tcp.time_delta']

# Verify columns exist
for col in FEATURES:
    if col not in df.columns:
        raise ValueError(
            f"Column '{col}' not found in dataset.\n"
            f"Available columns: {df.columns.tolist()}"
        )

df = df.dropna(subset=FEATURES)
print(f"[3] After dropping NaN in features: {len(df)} rows")

X = df[FEATURES].values.astype(np.float32)
y = (df['target'] == 'dos').astype(int).values   # 1=attack, 0=benign

print(f"    Benign samples : {(y==0).sum()}")
print(f"    Attack samples : {(y==1).sum()}\n")

# ── 3. Train / test split (80/20 — paper Section 6.3) ─────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"[4] Train: {len(X_train)} | Test: {len(X_test)}")

# ── 4. Train Random Forest ─────────────────────────────────────────────────
print("[5] Training Random Forest ...")
rf = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)
rf.fit(X_train, y_train)

# ── 5. Evaluate ────────────────────────────────────────────────────────────
y_pred = rf.predict(X_test)
acc    = accuracy_score(y_test, y_pred)
print(f"\n[6] Test Accuracy : {acc * 100:.2f}%")
print("    (Paper reports ~95.92% for Random Forest)")
print("\n    Classification Report:")
print(classification_report(y_test, y_pred, target_names=['benign', 'attack']))

# ── 6. Save ────────────────────────────────────────────────────────────────
MODEL_OUT = "rf_model.pkl"
with open(MODEL_OUT, "wb") as f:
    pickle.dump(rf, f)
print(f"[7] Model saved → {MODEL_OUT}")
print(f"\n    Copy {MODEL_OUT} to RPi 5 alongside mqttsec_broker.py")
print("    Done.")

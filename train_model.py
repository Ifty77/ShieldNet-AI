"""Train the ML layer.

The feature list comes from the canonical module, so the column order used at
training time is guaranteed to be the order used at prediction time.
"""

import os

import joblib
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from src.hybrid_waf.core.request_parser import FEATURE_ORDER

df = pd.read_csv("data/waf_dataset.csv")

missing = [c for c in FEATURE_ORDER if c not in df.columns]
if missing:
    raise SystemExit(
        f"Dataset is missing columns {missing}. Rerun generate_dataset.py."
    )

X = df[FEATURE_ORDER]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = LGBMClassifier(random_state=42, verbose=-1)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)

print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))

os.makedirs("src/hybrid_waf/models", exist_ok=True)
joblib.dump(model, "src/hybrid_waf/models/ml_model.pkl")
print("\nModel saved to: src/hybrid_waf/models/ml_model.pkl")
print("Feature order:", FEATURE_ORDER)

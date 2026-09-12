import pandas as pd
import joblib
from lightgbm import LGBMClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Load dataset
df = pd.read_csv("data/waf_dataset.csv")

# Exact feature order
feature_cols = [
    "URI_Length",
    "GET_Length",
    "POST_Length",
    "URI_Entropy",
    "GET_Entropy",
    "POST_Entropy",
    "Numeric_Text_Ratio",
    "Special_Char_Count",
]

X = df[feature_cols]
y = df["label"]

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Create model
model = LGBMClassifier(random_state=42)

# Train
model.fit(X_train, y_train)

# Predict
y_pred = model.predict(X_test)

# Evaluation
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))

# Save model
joblib.dump(model, "src/hybrid_waf/models/ml_model.pkl")
print("\nModel saved to: src/hybrid_waf/models/ml_model.pkl")
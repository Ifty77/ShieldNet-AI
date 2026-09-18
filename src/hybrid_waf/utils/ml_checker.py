import os

import joblib
import pandas as pd

from src.hybrid_waf.core.request_parser import FEATURE_ORDER

# Resolve relative to this file, not the working directory. The old relative
# path only worked when the app happened to be launched from the project root.
_HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.normpath(os.path.join(_HERE, "..", "models", "ml_model.pkl"))

_model = None


def get_model():
    """Load and cache the model. Raises if the file is missing or unreadable."""
    global _model
    if _model is None:
        _model = joblib.load(MODEL_PATH)
    return _model


def to_frame(features) -> pd.DataFrame:
    """Build a one-row DataFrame with named columns in canonical order.

    Using named columns lets scikit-learn/LightGBM validate that the columns it
    was trained on are the columns it is being asked to predict on. If the
    feature set ever drifts again, this raises instead of silently scoring
    garbage.
    """
    if isinstance(features, dict):
        row = [features[name] for name in FEATURE_ORDER]
    else:
        row = list(features)
    return pd.DataFrame([row], columns=FEATURE_ORDER)


def check_ml_prediction(features) -> int:
    """Predict from a feature dict (preferred) or an ordered feature list."""
    return int(get_model().predict(to_frame(features))[0])

"""Backwards-compatible shim.

The real implementation now lives in src/hybrid_waf/core/request_parser.py so
that training and serving share one definition. This module re-exports it and
is kept only so older imports keep working.
"""

from src.hybrid_waf.core.request_parser import (  # noqa: F401
    FEATURE_ORDER,
    extract_features_from_parts,
    features_to_list,
    numeric_text_ratio,
    shannon_entropy,
    special_char_count,
)


def extract_features(uri: str, get_data: str, post_data: str) -> list:
    """Deprecated. Returns the canonical feature list in FEATURE_ORDER."""
    return features_to_list(extract_features_from_parts(uri, get_data, post_data))

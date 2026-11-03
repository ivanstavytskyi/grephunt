"""Sentence embeddings for clustering findings by meaning (optional).

TF-IDF joins findings that share words. Embeddings also join findings that say
the same thing in different words ("EC2 Instance Monitoring Disabled" and
"Ensure that detailed monitoring is enabled for EC2 instances").

The model is model2vec's potion-base-8M: a sentence-transformer distilled into
static vectors (about 30 MB, numpy only, no PyTorch, fast on CPU). It is
downloaded once with `python -m grephunt models download` into data/models and
then used offline. Without the package or the model, clustering uses TF-IDF
alone and nothing fails.
"""
from __future__ import annotations

import functools
import logging
import os
from collections.abc import Sequence
from pathlib import Path

from grephunt.config import DATA_DIR

log = logging.getLogger(__name__)

DEFAULT_MODEL = "minishlab/potion-base-8M"
EMBEDDING_THRESHOLD = 0.78
"""Cosine similarity at or above which two unclassified findings on close lines are one problem."""


def model_name() -> str:
    return os.environ.get("GREPHUNT_EMBEDDINGS", DEFAULT_MODEL).strip()


def model_dir(name: str | None = None) -> Path:
    name = name or model_name()
    return DATA_DIR / "models" / name.replace("/", "--")


def enabled() -> bool:
    return model_name().lower() not in {"", "off", "none", "0", "false"}


@functools.lru_cache(maxsize=1)
def _load(path: str):
    try:
        from model2vec import StaticModel
    except ImportError:
        log.info("model2vec is not installed; findings are clustered with TF-IDF only")
        return None
    try:
        return StaticModel.from_pretrained(path)
    except Exception as exc:  # noqa: BLE001  A missing or broken model must not stop a scan.
        log.warning("embedding model at %s could not be loaded (%s); using TF-IDF only", path, exc)
        return None


def get_model():
    """The local model, or None. Never downloads during a scan."""
    if not enabled():
        return None
    folder = model_dir()
    if not folder.is_dir():
        return None
    return _load(str(folder))


def download(name: str | None = None) -> Path:
    """Fetch the model once into data/models (needs network)."""
    from model2vec import StaticModel

    name = name or model_name()
    folder = model_dir(name)
    model = StaticModel.from_pretrained(name)
    folder.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(folder))
    _load.cache_clear()
    return folder


def similarity_matrix(texts: Sequence[str], model=None) -> list[list[float]] | None:
    """Cosine similarities between texts, or None when no model is available."""
    model = model if model is not None else get_model()
    if model is None or not texts:
        return None
    import numpy as np

    vectors = np.asarray(model.encode(list(texts)), dtype="float32")
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    vectors = vectors / norms
    return (vectors @ vectors.T).tolist()

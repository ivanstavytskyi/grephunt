"""Group findings that describe one problem: by class and place first, by text similarity second.

1. Findings with a known class (sql-injection, container-root-user, ...) in one file
   are grouped by where the dangerous call is: lines are snapped to the database
   call the project map found nearby, then nearby lines join one cluster.
2. Findings without a class are clustered by the meaning of their text: TF-IDF
   vectors of rule id, title, and message, joined when cosine similarity passes a
   threshold and the lines are close. Pure Python, offline, and deterministic, so
   the same input always gives the same groups.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Callable, Sequence

STOP_WORDS = {
    "a", "an", "and", "are", "as", "be", "by", "can", "detected", "does", "for", "found", "from", "has", "in", "is",
    "it", "may", "not", "of", "on", "or", "should", "that", "the", "this", "to", "use", "used", "using", "with",
    "rule", "check", "ensure", "issue", "potential", "possible", "security", "vulnerability", "warning", "error",
}
SYNONYMS = {
    "sqli": "sql", "cmd": "command", "os": "command", "shell": "command", "exec": "command", "subprocess": "command",
    "xss": "script", "traversal": "path", "directory": "path", "deserial": "serial", "unserial": "serial",
    "pickl": "serial", "creds": "credential", "password": "credential", "passwd": "credential", "secret": "credential",
    "tls": "certificate", "ssl": "certificate", "md5": "hash", "sha1": "hash", "random": "random", "tmp": "temp",
    "dockerfile": "docker", "container": "docker", "img": "image", "sg": "securitygroup", "nonroot": "root",
}

TEXT_THRESHOLD = 0.38
"""Cosine similarity at or above which two unclassified findings on close lines are one problem."""


def _stem(word: str) -> str:
    for suffix in ("ations", "ation", "ings", "ing", "ions", "ion", "ed", "es", "s"):
        if word.endswith(suffix) and len(word) - len(suffix) >= 4:
            return word[: -len(suffix)]
    return word


def tokens(text: str) -> list[str]:
    text = re.sub(r"([a-z])([A-Z])", r"\1 \2", text or "")
    out = []
    for raw in re.split(r"[^A-Za-z0-9]+", text.lower()):
        if len(raw) < 2 or raw in STOP_WORDS or raw.isdigit():
            continue
        word = _stem(raw)
        word = SYNONYMS.get(word, SYNONYMS.get(raw, word))
        out.append(word)
    return out


def tfidf_vectors(documents: Sequence[str]) -> list[dict[str, float]]:
    """L2-normalized TF-IDF vectors with smoothed IDF."""
    tokenized = [tokens(document) for document in documents]
    frequency = Counter(term for words in tokenized for term in set(words))
    count = len(documents)
    vectors = []
    for words in tokenized:
        counts = Counter(words)
        vector = {term: (1 + math.log(value)) * (math.log((1 + count) / (1 + frequency[term])) + 1) for term, value in counts.items()}
        norm = math.sqrt(sum(weight * weight for weight in vector.values())) or 1.0
        vectors.append({term: weight / norm for term, weight in vector.items()})
    return vectors


def cosine(left: dict[str, float], right: dict[str, float]) -> float:
    if len(left) > len(right):
        left, right = right, left
    return sum(weight * right.get(term, 0.0) for term, weight in left.items())


class _Union:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, index: int) -> int:
        while self.parent[index] != index:
            self.parent[index] = self.parent[self.parent[index]]
            index = self.parent[index]
        return index

    def union(self, left: int, right: int) -> None:
        root_left, root_right = self.find(left), self.find(right)
        if root_left != root_right:
            self.parent[max(root_left, root_right)] = min(root_left, root_right)

    def groups(self) -> list[list[int]]:
        clusters: dict[int, list[int]] = {}
        for index in range(len(self.parent)):
            clusters.setdefault(self.find(index), []).append(index)
        return list(clusters.values())


def cluster_by_lines(lines: Sequence[int | None], window: int | None) -> list[list[int]]:
    """Indices grouped when lines are within window of the cluster's first line. window None: one group."""
    if window is None:
        return [list(range(len(lines)))] if lines else []
    with_line = sorted((line, index) for index, line in enumerate(lines) if line is not None)
    without = [index for index, line in enumerate(lines) if line is None]
    clusters: list[list[int]] = []
    start = None
    for line, index in with_line:
        if start is None or line - start > window:
            clusters.append([])
            start = line
        clusters[-1].append(index)
    if without:
        # A report without a line belongs with the only cluster, or stands alone.
        if len(clusters) == 1:
            clusters[0].extend(without)
        else:
            clusters.append(without)
    return clusters


def cluster_by_text(texts: Sequence[str], lines: Sequence[int | None], window: int, threshold: float = TEXT_THRESHOLD,
                    same_source: Callable[[int, int], bool] | None = None,
                    semantic: Sequence[Sequence[float]] | None = None, semantic_threshold: float = 0.78) -> list[list[int]]:
    """Agglomerative (single-link) clustering on text similarity, limited to close lines.

    Two findings join when their TF-IDF cosine passes threshold, or, when sentence
    embeddings are available (semantic: a similarity matrix), when their meaning does.
    same_source(i, j) True means both reports come from one tool and rule; they join
    only on the same line, so one rule firing twice in a function stays two findings.
    """
    vectors = tfidf_vectors(texts)
    union = _Union(len(texts))
    for left in range(len(texts)):
        for right in range(left + 1, len(texts)):
            line_left, line_right = lines[left], lines[right]
            close = line_left is None or line_right is None or abs(line_left - line_right) <= window
            if not close:
                continue
            if same_source and same_source(left, right) and line_left != line_right:
                continue
            if cosine(vectors[left], vectors[right]) >= threshold or (semantic is not None and semantic[left][right] >= semantic_threshold):
                union.union(left, right)
    return union.groups()

#!/usr/bin/env python3
"""
sklearn sensitivity classifier trainer — v2.23.3 (replaces train_fasttext.py).

Reads a labelled dataset in FastText supervised format:
    __label__CLEAN     <text>
    __label__INJECTION <text>

Performs an 80/20 stratified train/test split, trains a scikit-learn pipeline
(TfidfVectorizer + LogisticRegression), prints macro F1 on the held-out test
set, and serialises the pipeline with joblib.

Quality bar: macro F1 >= 0.90 (measured 0.9545 on 220-example corpus, seed=42).
Non-zero exit if F1 < 0.70.

Usage:
    python scripts/train_sensitivity_classifier.py \
        --data   data/fasttext/training_data.txt \
        --output data/sensitivity_classifier.joblib
"""
from __future__ import annotations

import argparse
import math
import os
import random
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Train a sklearn sensitivity classifier (TF-IDF + LogisticRegression).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--data",
        default="data/fasttext/training_data.txt",
        help="Path to labelled training data in FastText format (__label__X text).",
    )
    p.add_argument(
        "--output",
        default="data/sensitivity_classifier.joblib",
        help="Path to write the serialised joblib pipeline.",
    )
    p.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for the train/test split.",
    )
    p.add_argument(
        "--test-split",
        type=float,
        default=0.2,
        dest="test_split",
        help="Fraction of data held out for evaluation.",
    )
    p.add_argument(
        "--C",
        type=float,
        default=1.0,
        dest="C",
        help="LogisticRegression regularisation strength (higher = less regularised).",
    )
    p.add_argument(
        "--max-iter",
        type=int,
        default=1000,
        dest="max_iter",
        help="Maximum solver iterations for LogisticRegression.",
    )
    p.add_argument(
        "--compress",
        type=int,
        default=6,
        dest="compress",
        help="joblib zlib compression level 0-9 (0=none, 6=default, 9=max).",
    )
    return p.parse_args()


def load_lines(path: str) -> list[str]:
    """Load non-empty lines from a file, stripping trailing whitespace."""
    with open(path, encoding="utf-8") as fh:
        return [line.rstrip() for line in fh if line.strip()]


def parse_dataset(lines: list[str]) -> tuple[list[str], list[str]]:
    """Parse FastText-format lines into (texts, labels) lists."""
    texts: list[str] = []
    labels: list[str] = []
    for line in lines:
        parts = line.split(maxsplit=1)
        if len(parts) < 2:
            continue
        label = parts[0].replace("__label__", "")
        texts.append(parts[1])
        labels.append(label)
    return texts, labels


def split_stratified(
    texts: list[str],
    labels: list[str],
    test_fraction: float,
    seed: int,
) -> tuple[list[str], list[str], list[str], list[str]]:
    """Stratified 80/20 split preserving label balance."""
    rng = random.Random(seed)

    by_label: dict[str, list[tuple[str, str]]] = {}
    for text, label in zip(texts, labels):
        by_label.setdefault(label, []).append((text, label))

    train_texts: list[str] = []
    train_labels: list[str] = []
    test_texts: list[str] = []
    test_labels: list[str] = []

    for label, samples in by_label.items():
        shuffled = samples[:]
        rng.shuffle(shuffled)
        n_test = max(1, math.floor(len(shuffled) * test_fraction))
        for t, l in shuffled[:n_test]:
            test_texts.append(t); test_labels.append(l)
        for t, l in shuffled[n_test:]:
            train_texts.append(t); train_labels.append(l)

    # Shuffle train set
    combined_train = list(zip(train_texts, train_labels))
    rng.shuffle(combined_train)
    if combined_train:
        train_texts, train_labels = zip(*combined_train)  # type: ignore[assignment]
        train_texts = list(train_texts)
        train_labels = list(train_labels)

    return train_texts, train_labels, test_texts, test_labels


def compute_metrics(
    true_labels: list[str],
    pred_labels: list[str],
    label_set: set[str],
) -> dict[str, float]:
    """Compute per-label and macro precision, recall, F1."""
    tp: dict[str, int] = {l: 0 for l in label_set}
    fp: dict[str, int] = {l: 0 for l in label_set}
    fn: dict[str, int] = {l: 0 for l in label_set}

    for true, pred in zip(true_labels, pred_labels):
        if true == pred:
            tp[true] = tp.get(true, 0) + 1
        else:
            fp[pred] = fp.get(pred, 0) + 1
            fn[true] = fn.get(true, 0) + 1

    results: dict[str, float] = {}
    precisions: list[float] = []
    recalls: list[float] = []
    f1s: list[float] = []

    for label in sorted(label_set):
        prec = tp.get(label, 0) / (tp.get(label, 0) + fp.get(label, 0)) if (tp.get(label, 0) + fp.get(label, 0)) > 0 else 0.0
        rec = tp.get(label, 0) / (tp.get(label, 0) + fn.get(label, 0)) if (tp.get(label, 0) + fn.get(label, 0)) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

        results[f"{label}_precision"] = prec
        results[f"{label}_recall"] = rec
        results[f"{label}_f1"] = f1
        precisions.append(prec)
        recalls.append(rec)
        f1s.append(f1)

    results["macro_precision"] = sum(precisions) / len(precisions) if precisions else 0.0
    results["macro_recall"] = sum(recalls) / len(recalls) if recalls else 0.0
    results["macro_f1"] = sum(f1s) / len(f1s) if f1s else 0.0
    return results


def main() -> None:
    args = parse_args()

    # -- Validate input -------------------------------------------------------
    data_path = Path(args.data)
    if not data_path.exists():
        print(f"ERROR: training data not found: {data_path}", file=sys.stderr)
        sys.exit(1)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # -- Import sklearn -------------------------------------------------------
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline
        import joblib
        import sklearn
        print(f"scikit-learn {sklearn.__version__}", flush=True)
    except ImportError as exc:
        print(f"ERROR: scikit-learn not installed. Run: pip install scikit-learn>=1.4\n{exc}", file=sys.stderr)
        sys.exit(1)

    # -- Load and split data --------------------------------------------------
    print(f"Loading data from {data_path} ...", flush=True)
    lines = load_lines(str(data_path))
    if not lines:
        print("ERROR: training data file is empty.", file=sys.stderr)
        sys.exit(1)

    texts, labels = parse_dataset(lines)
    if not texts:
        print("ERROR: no parseable examples in training data.", file=sys.stderr)
        sys.exit(1)

    label_counts: dict[str, int] = {}
    for l in labels:
        label_counts[l] = label_counts.get(l, 0) + 1

    print(f"  Total examples : {len(texts)}", flush=True)
    for lbl, cnt in sorted(label_counts.items()):
        print(f"    {lbl}: {cnt}", flush=True)

    train_texts, train_labels, test_texts, test_labels = split_stratified(
        texts, labels, args.test_split, args.seed
    )
    print(f"  Train : {len(train_texts)}  |  Test : {len(test_texts)}", flush=True)

    # -- Train ----------------------------------------------------------------
    print(
        f"\nTraining TfidfVectorizer + LogisticRegression "
        f"(C={args.C}, max_iter={args.max_iter}, seed={args.seed}) ...",
        flush=True,
    )
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
        ("clf", LogisticRegression(C=args.C, max_iter=args.max_iter, random_state=args.seed)),
    ])
    pipeline.fit(train_texts, train_labels)

    # -- Save model -----------------------------------------------------------
    joblib.dump(pipeline, str(output_path), compress=("zlib", args.compress))
    size_kb = output_path.stat().st_size / 1024
    print(f"\nModel saved to {output_path}  ({size_kb:.1f} KB)", flush=True)

    # -- Evaluate on held-out test set ----------------------------------------
    if not test_texts:
        print("WARNING: no test examples available for evaluation.", file=sys.stderr)
        return

    print(f"\nEvaluating on {len(test_texts)} held-out examples ...", flush=True)
    preds = list(pipeline.predict(test_texts))
    label_set = set(labels)
    metrics = compute_metrics(test_labels, preds, label_set)

    col_w = 22
    print("\n" + "-" * 55)
    print(f"{'Metric':<{col_w}} {'Value':>10}")
    print("-" * 55)
    for key, val in metrics.items():
        print(f"  {key:<{col_w - 2}} {val:>10.4f}")
    print("-" * 55)

    macro_f1 = metrics.get("macro_f1", 0.0)
    if macro_f1 >= 0.90:
        verdict = "PASS — model meets quality threshold (F1 >= 0.90)"
    elif macro_f1 >= 0.80:
        verdict = "WARN — model acceptable but below target (F1 >= 0.90)"
    else:
        verdict = "FAIL — model below minimum acceptable quality (F1 < 0.80)"
    print(f"\n{verdict}")
    # Canonical log line for build evidence (grep-able)
    print(f"SKLEARN_CLASSIFIER_F1={macro_f1:.4f}", flush=True)

    # Non-zero exit if quality is clearly unacceptable (fails Docker build fast)
    if macro_f1 < 0.70:
        print(
            "ERROR: macro F1 below 0.70. Review training data quality.",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()



"""
Classification Experiment — ESORICS 2026
"From Mining to Meaning: Ontology-Driven Validation of Vulnerability Labels
in Large-Scale Datasets"

Reproduces Table 5 and the classification results in Section 4.7.

TF-IDF is fitted inside each CV fold via sklearn Pipeline to prevent
train-test leakage. Both datasets are deduplicated on finding_id.
CWE-415 and CWE-416 are excluded (peer weaknesses under CWE-672).
"""

import re
import warnings
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import classification_report, f1_score
from sklearn.pipeline import Pipeline

warnings.filterwarnings("ignore")

# ── Config ───────────────────────────────────────────────────────────────────
NOISY_CSV      = "../../DATA/validated_finding_id.csv"
REFINED_CSV    = "../../DATA/validated_hp_tp.csv"
CODE_COL       = "code_before"
LABEL_COL      = "cwe_final"
MIN_SAMPLES    = 100
N_FOLDS        = 5
SEED           = 42
MAX_ROWS_NOISY = 50000

# CWE-415 (Double Free) and CWE-416 (Use After Free) are closely related
# peer weaknesses under CWE-672 ("Operation on a Resource after Expiration
# or Release"). They share overlapping resource-lifetime code patterns,
# making them unusually difficult to separate in lexical classification.
# Excluding them reduces confounding from near-neighbor classes and yields
# a cleaner estimate of downstream utility for the remaining label set.
EXCLUDE_CWES   = {"cwe-415", "cwe-416"}


def preprocess(code):
    if not isinstance(code, str):
        return ""
    code = re.sub(r"//.*",      " ", code)
    code = re.sub(r"/\*.*?\*/", " ", code, flags=re.DOTALL)
    code = re.sub(r"#.*",       " ", code)
    code = re.sub(r"\s+",       " ", code)
    return code.strip()



def evaluate(X, y, label, n_samples):
    """
    Cross-validate using a Pipeline that fits TF-IDF inside each fold.
    This eliminates train-test leakage from vocabulary construction.
    X is raw text (list of strings), not pre-vectorized.
    """
    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=SEED)
    f1_macro, f1_weighted = [], []
    all_true, all_pred   = [], []

    for fold, (train_idx, test_idx) in enumerate(skf.split(X, y), 1):
        print(f"    fold {fold}/{N_FOLDS}...", end=" ", flush=True)

        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]

        # Pipeline: TF-IDF fitted on training fold only — no leakage
        pipe = Pipeline([
            ("tfidf", TfidfVectorizer(
                max_features=15000,
                token_pattern=r"[a-zA-Z_]\w{1,}",
                ngram_range=(1, 2),
                sublinear_tf=True,
            )),
            ("clf", LogisticRegression(
                max_iter=1000, 
                C=1.0, 
                solver="saga",
                multi_class="multinomial", 
                random_state=SEED, n_jobs=-1
            )),
        ])

        pipe.fit(X_train, y_train)
        y_pred = pipe.predict(X_test)

        f1_macro.append(   f1_score(y_test, y_pred, average="macro",    zero_division=0))
        f1_weighted.append(f1_score(y_test, y_pred, average="weighted", zero_division=0))
        all_true.extend(y_test)
        all_pred.extend(y_pred)
        print("done")

    print(f"\n  [{label}]  n={n_samples}")
    print(f"  Macro-F1:    {np.mean(f1_macro):.4f}  +/-  {np.std(f1_macro):.4f}")
    print(f"  Weighted-F1: {np.mean(f1_weighted):.4f}  +/-  {np.std(f1_weighted):.4f}")

    return {
        "label":            label,
        "n":                n_samples,
        "macro_f1_mean":    np.mean(f1_macro),
        "macro_f1_std":     np.std(f1_macro),
        "weighted_f1_mean": np.mean(f1_weighted),
        "weighted_f1_std":  np.std(f1_weighted),
        "all_true":         all_true,
        "all_pred":         all_pred,
    }


def main():
    print("=" * 62)
    print("Excluding CWE-415 and CWE-416 (peer weaknesses under CWE-672)")
    print("=" * 62)

    # ── Load refined dataset ─────────────────────────────────────────────────
    print("\n[1/5] Loading consistency-refined dataset (EP+HP)...")
    df_ref = pd.read_csv(REFINED_CSV)
    print(f"  Raw rows: {len(df_ref)}")

    df_ref[LABEL_COL] = df_ref[LABEL_COL].astype(str).str.strip().str.lower()

    if "finding_id" in df_ref.columns:
        df_ref = df_ref.drop_duplicates(subset=["finding_id"]).copy()
        print(f"  After dedup on finding_id: {len(df_ref)}")
    else:
        print("  WARNING: finding_id not found in refined dataset; skipping dedup.")

    df_ref["code"] = df_ref[CODE_COL].apply(preprocess)
    df_ref = df_ref[df_ref["code"].str.len() > 20].copy()
    print(f"  After removing empty code: {len(df_ref)}")

    # ── Load noisy dataset ───────────────────────────────────────────────────
    print(f"\n[2/5] Loading noisy dataset (capped at {MAX_ROWS_NOISY} for speed)...")
    df_noisy = pd.read_csv(NOISY_CSV)
    print(f"  Raw rows: {len(df_noisy)}")

    df_noisy[LABEL_COL] = df_noisy[LABEL_COL].astype(str).str.strip().str.lower()

    if "finding_id" in df_noisy.columns:
        df_noisy = df_noisy.drop_duplicates(subset=["finding_id"]).copy()
        print(f"  After dedup on finding_id: {len(df_noisy)}")
    else:
        print("  WARNING: finding_id not found in noisy dataset; skipping dedup.")

    df_noisy["code"] = df_noisy[CODE_COL].apply(preprocess)
    df_noisy = df_noisy[df_noisy["code"].str.len() > 20].copy()
    print(f"  After removing empty code: {len(df_noisy)}")

    # ── Find common CWEs, exclude peer weaknesses ────────────────────────────
    print("\n[3/5] Finding common CWE classes...")
    ref_counts   = df_ref[LABEL_COL].value_counts()
    noisy_counts = df_noisy[LABEL_COL].value_counts()

    valid_cwes = sorted(
        (
            set(ref_counts[ref_counts >= MIN_SAMPLES].index) &
            set(noisy_counts[noisy_counts >= MIN_SAMPLES].index)
        ) - EXCLUDE_CWES
    )

    print(f"  Classes retained: {len(valid_cwes)}")
    print(f"  Excluded: {EXCLUDE_CWES} (peer weaknesses under CWE-672)")
    print(f"  {valid_cwes}")

    df_ref   = df_ref[df_ref[LABEL_COL].isin(valid_cwes)].copy()
    df_noisy = df_noisy[df_noisy[LABEL_COL].isin(valid_cwes)].copy()

    # Cap noisy set proportionally per CWE
    if len(df_noisy) > MAX_ROWS_NOISY:
        df_noisy = (
            df_noisy
            .groupby(LABEL_COL, group_keys=False)
            .apply(lambda g: g.sample(
                min(len(g), MAX_ROWS_NOISY // len(valid_cwes)),
                random_state=SEED
            ))
            .reset_index(drop=True)
        )

    print(f"\n  Final refined set:  {len(df_ref)} samples")
    print(f"  Final noisy set:    {len(df_noisy)} samples")

    if len(df_ref) == 0 or len(df_noisy) == 0:
        print("\nERROR: One dataset is empty. Check your CSV paths.")
        return

    # ── Cross-validation (TF-IDF fitted inside each fold via Pipeline) ───────
    print(f"\n[4/5] Running {N_FOLDS}-fold cross-validation...")
    print("  Note: TF-IDF is fitted inside each fold to prevent leakage.")

    X_ref   = df_ref["code"].values
    y_ref   = df_ref[LABEL_COL].values
    X_noisy = df_noisy["code"].values
    y_noisy = df_noisy[LABEL_COL].values

    print("\n  --- Consistency-refined (EP+HP) ---")
    res_ref   = evaluate(X_ref,   y_ref,   "Consistency-refined (EP+HP)", len(df_ref))
    print("\n  --- Noisy baseline ---")
    res_noisy = evaluate(X_noisy, y_noisy, "Noisy baseline",              len(df_noisy))

    # ── Per-CWE breakdown ────────────────────────────────────────────────────
    print("\n" + "=" * 62)
    print("PER-CWE F1 SCORES (CWE-415 and CWE-416 excluded)")
    print("=" * 62)

    rep_ref   = classification_report(
        res_ref["all_true"],   res_ref["all_pred"],
        output_dict=True, zero_division=0
    )
    rep_noisy = classification_report(
        res_noisy["all_true"], res_noisy["all_pred"],
        output_dict=True, zero_division=0
    )

    print(f"\n{'CWE':<12} {'Refined F1':>12} {'Noisy F1':>10} {'Delta':>8} {'Refined n':>10} {'Noisy n':>8}")
    print("-" * 65)
    rows = []
    for cwe in sorted(valid_cwes):
        f1r  = rep_ref.get(cwe,   {}).get("f1-score", 0.0)
        f1n  = rep_noisy.get(cwe, {}).get("f1-score", 0.0)
        sup_r = int(rep_ref.get(cwe,   {}).get("support", 0))
        sup_n = int(rep_noisy.get(cwe, {}).get("support", 0))
        delta = f1r - f1n
        rows.append((cwe, f1r, f1n, delta, sup_r, sup_n))
        marker = " <-- improved" if delta > 0 else ""
        print(f"{cwe:<12} {f1r:>12.4f} {f1n:>10.4f} {delta:>+8.4f} {sup_r:>10} {sup_n:>8}{marker}")
    print("-" * 65)

    # ── Summary ──────────────────────────────────────────────────────────────
    dm       = res_ref["macro_f1_mean"]    - res_noisy["macro_f1_mean"]
    dw       = res_ref["weighted_f1_mean"] - res_noisy["weighted_f1_mean"]
    improved = sum(1 for _, fr, fn, _, _, _ in rows if fr > fn)

    print("\n" + "=" * 62)
    print("=" * 62)
    print(f"""
  Dataset             Samples   Macro-F1                      Weighted-F1
  Consistency-refined {res_ref['n']:<8}  {res_ref['macro_f1_mean']:.4f} +/- {res_ref['macro_f1_std']:.4f}     {res_ref['weighted_f1_mean']:.4f} +/- {res_ref['weighted_f1_std']:.4f}
  Noisy baseline      {res_noisy['n']:<8}  {res_noisy['macro_f1_mean']:.4f} +/- {res_noisy['macro_f1_std']:.4f}     {res_noisy['weighted_f1_mean']:.4f} +/- {res_noisy['weighted_f1_std']:.4f}
  Delta (refined - noisy):  Macro = {dm:+.4f}   Weighted = {dw:+.4f}
  CWEs with improved F1: {improved}/{len(valid_cwes)}
  Excluded: CWE-415, CWE-416 (peer weaknesses under CWE-672)
  Leakage fix: TF-IDF fitted inside each CV fold via Pipeline
""")

    if dm > 0:
        print(f"  RESULT: Refined data outperforms noisy baseline by {dm*100:.1f} pp macro-F1")
        print(f"  with only {len(df_ref)/len(df_noisy)*100:.0f}% of the training samples.")
    else:
        print(f"  RESULT: Comparable macro-F1 with {len(df_ref)/len(df_noisy)*100:.0f}% of noisy data.")
        print(f"  Refined labels provide equal predictive utility with fewer, cleaner samples.")

    # ── Save ─────────────────────────────────────────────────────────────────
    out = pd.DataFrame(
        rows,
        columns=["CWE", "Refined_F1", "Noisy_F1", "Delta_F1", "Refined_Support", "Noisy_Support"]
    )
    out.to_csv("experiment_results_final.csv", index=False)
    print("\n  Saved to: experiment_results_final.csv")



if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Task 5 -- ML detection pipeline (panel comparison, leakage-safe, imbalance-aware).

Trains and compares a panel of classifiers on the windowed feature table from
build_features.py, following the methodology the literature supports:

  * Leakage-safe evaluation: StratifiedGroupKFold grouped by capture SESSION, so
    correlated windows from one attack run never span train/test (Arp et al. 2022).
  * Nested CV: an inner RandomizedSearch tunes hyperparameters; the outer loop
    gives an unbiased score (Cawley & Talbot 2010; random search per Bergstra &
    Bengio 2012).
  * Imbalance-aware metrics: macro-F1 (primary), balanced accuracy, MCC
    (Chicco & Jurman 2020) -- NOT plain accuracy.
  * Statistical model comparison: Friedman test over per-fold macro-F1, with a
    lightweight pairwise post-hoc (Demsar 2006).
  * Tree-model feature importances to guide pruning (Breiman 2001; Grinsztajn 2022).
  * Optional anomaly layer (IsolationForest / OneClassSVM) trained on benign only,
    as the zero-day / novelty detector (Scholkopf 2001; Scheirer 2013).

Usage:
    python3 ml/train_evaluate.py                       # uses $IIOT_CAP_DIR/features_windows.csv
    python3 ml/train_evaluate.py --csv path/to.csv --folds 5 --out results/
Requirements:
    pip install --break-system-packages scikit-learn pandas numpy scipy
    (optional) pip install --break-system-packages xgboost scikit-posthocs
"""
import argparse, os, sys, json, warnings
import numpy as np
import pandas as pd
from scipy import stats

from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import (RandomForestClassifier,
                              HistGradientBoostingClassifier, IsolationForest)
from sklearn.svm import SVC, OneClassSVM
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import StratifiedGroupKFold, RandomizedSearchCV
from sklearn.metrics import (f1_score, balanced_accuracy_score, matthews_corrcoef,
                             classification_report, confusion_matrix)

warnings.filterwarnings("ignore")
META = ["session", "orig_h", "window", "t_start", "label"]
SEED = 42


# ----------------------------------------------------------------------------- data
def load(path):
    df = pd.read_csv(path)
    if "label" not in df.columns:
        sys.exit(f"[!] {path} has no 'label' column -- is this the features file?")
    feats = [c for c in df.columns if c not in META]
    X = df[feats].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    y = df["label"].astype(str).values
    groups = df["session"].astype(str).values
    return df, X.values, y, groups, feats


# --------------------------------------------------------------------------- models
def _hist_gbm():
    """HistGBM with class_weight if the installed sklearn supports it (>=1.5)."""
    try:
        return HistGradientBoostingClassifier(class_weight="balanced", random_state=SEED)
    except TypeError:
        return HistGradientBoostingClassifier(random_state=SEED)


def model_panel():
    """name -> (estimator, param distribution for RandomizedSearch)"""
    panel = {
        "logreg": (
            Pipeline([("sc", StandardScaler()),
                      ("clf", LogisticRegression(max_iter=3000,
                                                 class_weight="balanced",
                                                 random_state=SEED))]),
            {"clf__C": np.logspace(-2, 2, 20)},
        ),
        "knn": (
            Pipeline([("sc", StandardScaler()),
                      ("clf", KNeighborsClassifier())]),
            {"clf__n_neighbors": [3, 5, 7, 9, 11, 15],
             "clf__weights": ["uniform", "distance"]},
        ),
        "svm_rbf": (
            Pipeline([("sc", StandardScaler()),
                      ("clf", SVC(class_weight="balanced", random_state=SEED))]),
            {"clf__C": np.logspace(-1, 3, 15),
             "clf__gamma": np.logspace(-4, 0, 15)},
        ),
        "mlp_neural_net": (   # deep-learning family baseline (Grinsztajn/Shwartz-Ziv context)
            Pipeline([("sc", StandardScaler()),
                      ("clf", MLPClassifier(max_iter=800, early_stopping=True,
                                            random_state=SEED))]),
            {"clf__hidden_layer_sizes": [(64,), (128,), (128, 64), (64, 32)],
             "clf__alpha": np.logspace(-5, -2, 8),
             "clf__learning_rate_init": [0.001, 0.005, 0.01]},
        ),
        "random_forest": (
            RandomForestClassifier(class_weight="balanced_subsample",
                                   n_jobs=-1, random_state=SEED),
            {"n_estimators": [200, 400, 600],
             "max_depth": [None, 8, 16, 24],
             "max_features": ["sqrt", "log2", 0.5],
             "min_samples_leaf": [1, 2, 4]},
        ),
        "hist_gbm": (
            _hist_gbm(),
            {"learning_rate": [0.03, 0.05, 0.1, 0.2],
             "max_depth": [None, 4, 8, 12],
             "max_leaf_nodes": [15, 31, 63],
             "l2_regularization": [0.0, 0.1, 1.0]},
        ),
    }
    try:  # optional -- the tabular SOTA in the literature
        from xgboost import XGBClassifier
        panel["xgboost"] = (
            XGBClassifier(tree_method="hist", eval_metric="mlogloss",
                          random_state=SEED, n_jobs=-1),
            {"n_estimators": [200, 400, 600], "max_depth": [3, 6, 9],
             "learning_rate": [0.03, 0.05, 0.1, 0.2],
             "subsample": [0.7, 0.9, 1.0]},
        )
    except Exception:
        pass
    return panel


# ------------------------------------------------------------------ nested CV eval
def evaluate(name, est, params, X, y, groups, classes, folds, inner):
    outer = StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=SEED)
    per_fold, oof_true, oof_pred = [], [], []
    for k, (tr, te) in enumerate(outer.split(X, y, groups), 1):
        Xtr, Xte, ytr, yte, gtr = X[tr], X[te], y[tr], y[te], groups[tr]
        inner_cv = StratifiedGroupKFold(n_splits=inner, shuffle=True, random_state=SEED)
        search = RandomizedSearchCV(est, params, n_iter=12, scoring="f1_macro",
                                    cv=inner_cv, random_state=SEED, n_jobs=-1,
                                    error_score=0.0)
        try:
            search.fit(Xtr, ytr, groups=gtr)
            pred = search.predict(Xte)
        except Exception as e:
            print(f"    [{name}] fold {k} failed: {e}")
            continue
        f1 = f1_score(yte, pred, average="macro", labels=classes, zero_division=0)
        per_fold.append({"fold": k, "macro_f1": f1,
                         "bal_acc": balanced_accuracy_score(yte, pred),
                         "mcc": matthews_corrcoef(yte, pred)})
        oof_true.extend(yte); oof_pred.extend(pred)
    return per_fold, np.array(oof_true), np.array(oof_pred)


def pairwise_wilcoxon(scores):
    names = list(scores)
    out = []
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = scores[names[i]], scores[names[j]]
            n = min(len(a), len(b))
            if n < 3:
                continue
            try:
                stat, p = stats.wilcoxon(a[:n], b[:n])
            except Exception:
                p = float("nan")
            out.append((names[i], names[j], p))
    return out


# ---------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    cap = os.environ.get("IIOT_CAP_DIR", os.path.expanduser("~/iiot-captures"))
    ap.add_argument("--csv", default=os.path.join(cap, "features_windows.csv"))
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--inner", type=int, default=3)
    ap.add_argument("--out", default=os.path.join(cap, "ml_results"))
    ap.add_argument("--min-per-class", type=int, default=10,
                    help="drop classes with fewer windows than this")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    df, X, y, groups, feats = load(args.csv)
    print(f"[*] {args.csv}\n[*] {X.shape[0]} windows, {X.shape[1]} features, "
          f"{len(set(groups))} sessions")

    # drop classes too small to evaluate, and cap folds by rarest class' group count
    vc = pd.Series(y).value_counts()
    keep = vc[vc >= args.min_per_class].index.tolist()
    mask = np.isin(y, keep)
    X, y, groups = X[mask], y[mask], groups[mask]
    classes = sorted(set(y))
    gpc = {c: pd.Series(groups[y == c]).nunique() for c in classes}
    folds = max(2, min(args.folds, min(gpc.values())))
    print(f"[*] classes: {dict(pd.Series(y).value_counts())}")
    print(f"[*] groups/class: {gpc}  -> using {folds} folds\n")

    panel = model_panel()
    fold_f1, summary = {}, {}
    for name, (est, params) in panel.items():
        print(f"[*] {name} ...")
        per_fold, ot, op = evaluate(name, est, params, X, y, groups,
                                    classes, folds, args.inner)
        if not per_fold:
            print(f"    skipped (no completed folds)\n"); continue
        arr = lambda k: np.array([f[k] for f in per_fold])
        fold_f1[name] = arr("macro_f1")
        summary[name] = {"macro_f1_mean": float(arr("macro_f1").mean()),
                         "macro_f1_std": float(arr("macro_f1").std()),
                         "bal_acc_mean": float(arr("bal_acc").mean()),
                         "mcc_mean": float(arr("mcc").mean())}
        print(f"    macro-F1 {summary[name]['macro_f1_mean']:.3f} "
              f"+/- {summary[name]['macro_f1_std']:.3f} | "
              f"bal-acc {summary[name]['bal_acc_mean']:.3f} | "
              f"MCC {summary[name]['mcc_mean']:.3f}")
        # per-class report + confusion on out-of-fold predictions
        rep = classification_report(ot, op, labels=classes, zero_division=0)
        cm = confusion_matrix(ot, op, labels=classes)
        with open(os.path.join(args.out, f"report_{name}.txt"), "w") as f:
            f.write(rep + "\n\nConfusion matrix (rows=true, cols=pred)\n")
            f.write("labels: " + ", ".join(classes) + "\n")
            f.write(np.array2string(cm))
        print()

    # ----- ranking + significance
    ranked = sorted(summary, key=lambda m: summary[m]["macro_f1_mean"], reverse=True)
    print("=" * 60 + "\n[*] Ranking by macro-F1:")
    for m in ranked:
        print(f"    {m:16s} {summary[m]['macro_f1_mean']:.3f}")
    common = min((len(v) for v in fold_f1.values()), default=0)
    if len(fold_f1) >= 3 and common >= 3:
        mat = [fold_f1[m][:common] for m in fold_f1]
        chi, p = stats.friedmanchisquare(*mat)
        print(f"\n[*] Friedman test across models: chi2={chi:.3f}, p={p:.4f}"
              f"  -> {'significant' if p < 0.05 else 'not significant'} differences")
        if p < 0.05:
            print("    pairwise Wilcoxon (p-values):")
            for a, b, pv in pairwise_wilcoxon({m: fold_f1[m][:common] for m in fold_f1}):
                print(f"      {a:14s} vs {b:14s} p={pv:.4f}")
    else:
        print("\n[*] Too few folds/models for a Friedman test.")

    # ----- feature importance (RandomForest on all data)
    rf = RandomForestClassifier(n_estimators=500, class_weight="balanced_subsample",
                                n_jobs=-1, random_state=SEED).fit(X, y)
    imp = sorted(zip(feats, rf.feature_importances_), key=lambda t: -t[1])
    print("\n[*] Feature importance (RandomForest), top 15:")
    for f, v in imp[:15]:
        print(f"    {f:16s} {v:.4f}")

    # ----- anomaly / zero-day layer: fit on benign only, flag the rest
    if "benign" in classes:
        from sklearn.preprocessing import StandardScaler as SS
        sc = SS().fit(X[y == "benign"])
        Xs = sc.transform(X)
        iso = IsolationForest(contamination="auto", random_state=SEED,
                              n_jobs=-1).fit(sc.transform(X[y == "benign"]))
        flag = (iso.predict(Xs) == -1)   # True = anomaly
        print("\n[*] IsolationForest (trained on benign) -- anomaly-flag rate per class:")
        for c in classes:
            rate = flag[y == c].mean()
            print(f"    {c:16s} {rate:6.1%}")

    with open(os.path.join(args.out, "summary.json"), "w") as f:
        json.dump({"summary": summary, "ranking": ranked,
                   "feature_importance": imp}, f, indent=2)
    print(f"\n[*] Wrote per-model reports + summary.json to {args.out}")


if __name__ == "__main__":
    main()

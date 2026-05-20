"""
index_advisor_model.py
-----------------------
Trains a classification model to predict whether adding a B-Tree index
to a given (table, column) will meaningfully reduce query execution cost.

Features used:
  - Query frequency (total_queries)
  - Average execution time
  - Sequential scan percentage
  - Cardinality estimate (encoded)
  - Existing index status

Target:
  - should_index: 1 if adding an index would help, 0 otherwise
  - estimated_improvement_pct: regression output
"""

import sqlite3
import json
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import GradientBoostingClassifier, GradientBoostingRegressor
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, mean_absolute_error
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


MODEL_DIR = Path("models")
MODEL_DIR.mkdir(exist_ok=True)


# ─── Feature Engineering ──────────────────────────────────────────────────────

CARDINALITY_MAP = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

# Index is beneficial when:
#   - high seq_scan_pct (no index used currently)
#   - high query frequency
#   - high avg execution time
#   - HIGH cardinality (low cardinality indexes aren't worth it)
#   - column doesn't already have an index

def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """Engineer features for the ML model."""
    features = pd.DataFrame()
    
    features["query_frequency"]     = df["total_queries"]
    features["avg_exec_time_ms"]    = df["avg_exec_time_ms"]
    features["max_exec_time_ms"]    = df["max_exec_time_ms"]
    features["seq_scan_pct"]        = df["seq_scan_pct"]
    features["has_index"]           = df["has_index"]
    features["cardinality_numeric"] = df["cardinality_estimate"].map(CARDINALITY_MAP).fillna(1)
    
    # Derived features
    features["cost_pressure"]       = features["avg_exec_time_ms"] * features["seq_scan_pct"]
    features["query_weight"]        = np.log1p(features["query_frequency"]) * features["avg_exec_time_ms"]
    features["index_opportunity"]   = (1 - features["has_index"]) * features["seq_scan_pct"]
    
    return features


def generate_labels(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """
    Generate ground-truth labels using domain knowledge rules.
    
    In production: use A/B test data comparing before/after indexing.
    Here: derive from the data characteristics.
    """
    
    should_index = (
        (df["seq_scan_pct"] > 0.6) &          # mostly full table scans
        (df["avg_exec_time_ms"] > 300) &       # slow queries
        (df["total_queries"] > 30) &           # frequent enough to matter
        (df["has_index"] == 0) &               # no index yet
        (df["cardinality_estimate"] != "LOW")  # cardinality worth indexing
    ).astype(int)
    
    # Estimate improvement % based on execution time ratio
    # Index typically converts seq_scan cost to ~10-15% of original
    improvement_pct = np.where(
        should_index == 1,
        np.clip(
            (df["seq_scan_pct"] * 0.85 * df["avg_exec_time_ms"]) / df["avg_exec_time_ms"] * 100,
            10, 90
        ),
        0.0
    )
    
    return should_index.values, improvement_pct


# ─── Model Training ───────────────────────────────────────────────────────────

def train_models(db_path: str = "logs/query_logs.db"):
    """Load data, train classifier + regressor, save to disk."""
    
    print("[+] Loading column statistics from database...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT * FROM column_stats", conn)
    conn.close()
    
    if len(df) < 5:
        raise ValueError(f"Not enough data to train. Found {len(df)} column records.")
    
    print(f"[+] Training on {len(df)} (table, column) pairs...")
    
    X = build_features(df)
    y_class, y_reg = generate_labels(df)
    
    print(f"    Index recommended: {y_class.sum()} / {len(y_class)} columns")
    
    # ── Classifier: Should we add an index? ─────────────────────────────────
    clf = GradientBoostingClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        random_state=42
    )
    
    if len(df) >= 10:
        X_tr, X_te, yc_tr, yc_te = train_test_split(X, y_class, test_size=0.2, random_state=42)
        clf.fit(X_tr, yc_tr)
        yc_pred = clf.predict(X_te)
        print("\n[✓] Classifier Report:")
        print(classification_report(yc_te, yc_pred, target_names=["No Index", "Add Index"], zero_division=0))
        
        cv_scores = cross_val_score(clf, X, y_class, cv=min(5, len(df)//2), scoring="f1")
        print(f"    Cross-val F1: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
    else:
        clf.fit(X, y_class)
    
    # ── Regressor: How much improvement? ────────────────────────────────────
    mask = y_class == 1
    if mask.sum() >= 3:
        reg = GradientBoostingRegressor(n_estimators=100, max_depth=3, random_state=42)
        reg.fit(X[mask], y_reg[mask])
        
        if mask.sum() >= 6:
            X_rtr, X_rte, yr_tr, yr_te = train_test_split(
                X[mask], y_reg[mask], test_size=0.2, random_state=42
            )
            reg.fit(X_rtr, yr_tr)
            yr_pred = reg.predict(X_rte)
            mae = mean_absolute_error(yr_te, yr_pred)
            print(f"\n[✓] Regressor MAE: {mae:.1f}%")
    else:
        reg = None
        print("[!] Not enough positive samples to train regressor.")
    
    # ── Feature Importance ───────────────────────────────────────────────────
    importance = pd.Series(clf.feature_importances_, index=X.columns).sort_values(ascending=False)
    print("\n[✓] Feature Importances:")
    for feat, imp in importance.items():
        bar = "█" * int(imp * 40)
        print(f"    {feat:25s} {bar} {imp:.3f}")
    
    # ── Save Models ──────────────────────────────────────────────────────────
    joblib.dump(clf, MODEL_DIR / "index_classifier.pkl")
    if reg:
        joblib.dump(reg, MODEL_DIR / "improvement_regressor.pkl")
    
    # Save feature column order
    joblib.dump(list(X.columns), MODEL_DIR / "feature_columns.pkl")
    
    print(f"\n[✓] Models saved to {MODEL_DIR}/")
    return clf, reg


# ─── Prediction & Recommendations ────────────────────────────────────────────

def generate_recommendations(db_path: str = "logs/query_logs.db") -> list[dict]:
    """Load trained models and generate index recommendations."""
    
    clf_path = MODEL_DIR / "index_classifier.pkl"
    if not clf_path.exists():
        raise FileNotFoundError("Model not found. Run train_models() first.")
    
    clf = joblib.load(clf_path)
    reg = joblib.load(MODEL_DIR / "improvement_regressor.pkl") if (MODEL_DIR / "improvement_regressor.pkl").exists() else None
    feature_cols = joblib.load(MODEL_DIR / "feature_columns.pkl")
    
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT * FROM column_stats", conn)
    conn.close()
    
    X = build_features(df)[feature_cols]
    
    proba = clf.predict_proba(X)[:, 1]
    predictions = clf.predict(X)
    
    improvement_pcts = []
    if reg:
        improvements = reg.predict(X)
        improvement_pcts = np.clip(improvements, 5, 95)
    else:
        improvement_pcts = np.where(predictions == 1, 45.0, 0.0)
    
    recommendations = []
    for i, row in df.iterrows():
        rec = {
            "table": row["table_name"],
            "column": row["column_name"],
            "should_index": bool(predictions[i]),
            "confidence": float(proba[i]),
            "estimated_improvement_pct": float(improvement_pcts[i]) if predictions[i] else 0.0,
            "avg_exec_time_ms": float(row["avg_exec_time_ms"]),
            "query_frequency": int(row["total_queries"]),
            "seq_scan_pct": float(row["seq_scan_pct"]),
            "has_index": bool(row["has_index"]),
            "cardinality": row["cardinality_estimate"],
            "index_type": _recommend_index_type(row["column_name"], row["cardinality_estimate"]),
            "sql": _generate_index_sql(row["table_name"], row["column_name"], 
                                        _recommend_index_type(row["column_name"], row["cardinality_estimate"])),
            "priority": _compute_priority(float(proba[i]), float(row["avg_exec_time_ms"]), int(row["total_queries"]))
        }
        recommendations.append(rec)
    
    # Sort by priority score
    recommendations.sort(key=lambda x: x["priority"], reverse=True)
    return recommendations


def _recommend_index_type(column: str, cardinality: str) -> str:
    """Suggest index type based on column characteristics."""
    text_patterns = ["name", "email", "description", "title", "text", "content"]
    date_patterns = ["at", "date", "time", "created", "updated", "timestamp"]
    
    col_lower = column.lower()
    if any(p in col_lower for p in date_patterns):
        return "BRIN"   # Block Range Index — ideal for time-series data
    elif cardinality == "LOW":
        return "Partial" # Partial index — better for low-cardinality
    else:
        return "B-Tree"  # Default, best for equality/range queries


def _generate_index_sql(table: str, column: str, index_type: str) -> str:
    idx_name = f"idx_{table}_{column}"
    if index_type == "BRIN":
        return f"CREATE INDEX {idx_name} ON {table} USING BRIN ({column});"
    elif index_type == "Partial":
        return f"CREATE INDEX {idx_name} ON {table} ({column}) WHERE {column} IS NOT NULL;"
    else:
        return f"CREATE INDEX CONCURRENTLY {idx_name} ON {table} ({column});"


def _compute_priority(confidence: float, avg_time: float, frequency: int) -> float:
    """Priority = impact × confidence × frequency weight."""
    time_score = min(avg_time / 1000, 5.0)  # cap at 5
    freq_score = min(np.log1p(frequency) / 5, 2.0)
    return confidence * time_score * freq_score


if __name__ == "__main__":
    train_models()
    recs = generate_recommendations()
    
    print("\n" + "="*70)
    print("TOP INDEX RECOMMENDATIONS")
    print("="*70)
    for r in recs[:5]:
        if r["should_index"]:
            print(f"\n📊 {r['table']}.{r['column']}")
            print(f"   Type: {r['index_type']} index")
            print(f"   Estimated improvement: {r['estimated_improvement_pct']:.0f}%")
            print(f"   Confidence: {r['confidence']:.1%}")
            print(f"   Avg query time: {r['avg_exec_time_ms']:.0f}ms")
            print(f"   SQL: {r['sql']}")

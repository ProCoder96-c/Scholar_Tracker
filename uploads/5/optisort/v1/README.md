# 🧠 ML-Powered Database Index Advisor

> **Bridges DBMS Internals + Applied Machine Learning** — uses a Gradient Boosting classifier to analyze PostgreSQL query execution logs and recommend optimal indexes, complete with estimated performance improvements and ready-to-run SQL.

---

## Architecture

```
PostgreSQL Logs / pg_stat_statements
           │
           ▼
   query_ingester.py          ← Parses & aggregates query logs into SQLite
           │                     Tracks: frequency, exec time, seq scan %, col usage
           ▼
   index_advisor_model.py     ← Engineers features, trains GradientBoosting model
           │                     Outputs: should_index (classifier) + improvement % (regressor)
           ▼
   run.py  /  api.py          ← CLI + Flask REST API
           │
           ▼
   dashboard/index.html       ← Interactive recommendation console
```

---

## Quickstart

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the full pipeline (simulate logs → train → recommend → export SQL)
python run.py --all

# 3. Or run each step separately:
python run.py --ingest          # Generate/ingest 3000 query logs
python run.py --train           # Train ML model
python run.py --recommend       # Print recommendations to terminal
python run.py --report          # Write output_indexes.sql

# 4. Launch the Flask API (serves dashboard data)
python src/api.py

# 5. Open the dashboard
open dashboard/index.html
```

---

## ML Model Details

### Features Engineered
| Feature | Description |
|---|---|
| `query_frequency` | How often this column appears in WHERE clauses |
| `avg_exec_time_ms` | Mean query execution time over the window |
| `seq_scan_pct` | % of queries using sequential scans (no index) |
| `cardinality_numeric` | Encoded HIGH/MEDIUM/LOW column cardinality |
| `has_index` | Binary — does an index already exist? |
| `cost_pressure` | `avg_time × seq_scan_pct` — combined pain score |
| `query_weight` | `log(freq) × avg_time` — frequency-weighted cost |
| `index_opportunity` | `(1 - has_index) × seq_scan_pct` — addressable gap |

### Model
- **Classifier**: `GradientBoostingClassifier` (100 estimators, depth 4)
  - Predicts: *should we add an index to this column?*
  - Output: class (0/1) + confidence probability
- **Regressor**: `GradientBoostingRegressor`  
  - Predicts: *estimated % improvement in execution time*

### Index Type Selection Logic
```
BRIN index   → date/time columns (block-range efficient for time-series)
Partial index → LOW cardinality columns (status, country, boolean flags)
B-Tree index  → HIGH/MEDIUM cardinality (default, best for equality/range)
```

---

## Connecting to Real PostgreSQL

Replace `simulate_query_logs()` with real data from `pg_stat_statements`:

```sql
-- Enable in postgresql.conf
shared_preload_libraries = 'pg_stat_statements'

-- Query the view
SELECT
    query,
    calls,
    mean_exec_time,
    rows,
    shared_blks_hit,
    shared_blks_read
FROM pg_stat_statements
ORDER BY mean_exec_time DESC;
```

Then in `query_ingester.py`, replace `simulate_query_logs()` with:
```python
def ingest_from_postgres(conn_string: str):
    import psycopg2
    conn = psycopg2.connect(conn_string)
    cur = conn.cursor()
    cur.execute("""
        SELECT query, calls, mean_exec_time, rows,
               shared_blks_read, shared_blks_hit
        FROM pg_stat_statements
        WHERE calls > 10
        ORDER BY mean_exec_time DESC
        LIMIT 1000
    """)
    # ... parse and write to SQLite as before
```

---

## Output Example

```sql
-- orders.created_at: ~85% improvement | confidence 100%
CREATE INDEX idx_orders_created_at ON orders USING BRIN (created_at);

-- payments.amount: ~85% improvement | confidence 100%
CREATE INDEX CONCURRENTLY idx_payments_amount ON payments (amount);

-- users.email: ~85% improvement | confidence 100%  
CREATE INDEX CONCURRENTLY idx_users_email ON users (email);
```

---

## Project Structure

```
db-index-advisor/
├── src/
│   ├── query_ingester.py        # Log ingestion + column statistics
│   ├── index_advisor_model.py   # ML training + recommendation engine
│   └── api.py                   # Flask REST API
├── dashboard/
│   └── index.html               # Interactive web dashboard
├── models/
│   ├── index_classifier.pkl     # Trained GradientBoosting classifier
│   └── improvement_regressor.pkl
├── logs/
│   └── query_logs.db            # SQLite: raw logs + column stats
├── run.py                       # CLI entry point
├── output_indexes.sql           # Generated SQL (after --report)
└── requirements.txt
```

---

## Why This Project Stands Out

1. **Real DBMS problem** — not toy CSV analysis; addresses a genuine production pain point
2. **Full ML pipeline** — feature engineering, classification, regression, cross-validation
3. **Domain-aware design** — understands B-Tree vs BRIN vs Partial indexes, cardinality effects
4. **Production-ready output** — generates `CREATE INDEX CONCURRENTLY` to avoid table locks
5. **Extensible** — swap SQLite for real `pg_stat_statements`, add EXPLAIN ANALYZE parsing

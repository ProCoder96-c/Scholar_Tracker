"""
query_ingester.py
-----------------
Simulates and ingests PostgreSQL query execution logs.
In production: tail pg_stat_statements or parse log files.
For demo: generates realistic synthetic query patterns.
"""

import random
import time
import json
import sqlite3
import re
from datetime import datetime, timedelta
from pathlib import Path


# ─── Synthetic Query Templates ────────────────────────────────────────────────

QUERY_TEMPLATES = [
    # (query_template, base_cost, columns_used, table)
    ("SELECT * FROM orders WHERE user_id = %s",            850,  ["user_id"],            "orders"),
    ("SELECT * FROM orders WHERE status = %s",             2100, ["status"],              "orders"),
    ("SELECT * FROM orders WHERE created_at > %s",         3200, ["created_at"],          "orders"),
    ("SELECT * FROM users WHERE email = %s",               600,  ["email"],               "users"),
    ("SELECT * FROM users WHERE country = %s",             1800, ["country"],             "users"),
    ("SELECT * FROM products WHERE category_id = %s",      950,  ["category_id"],         "products"),
    ("SELECT * FROM products WHERE price < %s",            2700, ["price"],               "products"),
    ("SELECT * FROM sessions WHERE user_id = %s AND active = %s", 780, ["user_id","active"], "sessions"),
    ("SELECT * FROM payments WHERE order_id = %s",         430,  ["order_id"],            "payments"),
    ("SELECT * FROM payments WHERE amount > %s",           3100, ["amount"],              "payments"),
    ("SELECT * FROM logs WHERE event_type = %s",           4500, ["event_type"],          "logs"),
    ("SELECT * FROM logs WHERE user_id = %s AND created_at BETWEEN %s AND %s", 1200, ["user_id","created_at"], "logs"),
    ("SELECT * FROM inventory WHERE product_id = %s",      340,  ["product_id"],          "inventory"),
    ("SELECT * FROM reviews WHERE product_id = %s",        890,  ["product_id"],          "reviews"),
    ("SELECT COUNT(*) FROM orders WHERE user_id = %s",     720,  ["user_id"],             "orders"),
    ("SELECT * FROM orders JOIN users ON orders.user_id = users.id WHERE users.email = %s", 1650, ["email","user_id"], "orders,users"),
]

# Columns that already have indexes (realistic scenario)
EXISTING_INDEXES = {
    "orders.id", "users.id", "products.id", "sessions.id",
    "payments.id", "logs.id", "inventory.id", "reviews.id",
    "orders.user_id",  # already indexed — model should learn this
}


def extract_columns_from_query(sql: str) -> list[str]:
    """Parse SQL to extract WHERE clause columns."""
    columns = []
    where_match = re.search(r'WHERE\s+(.+?)(?:ORDER|GROUP|LIMIT|$)', sql, re.IGNORECASE | re.DOTALL)
    if where_match:
        where_clause = where_match.group(1)
        cols = re.findall(r'(\w+)\s*(?:=|>|<|>=|<=|!=|BETWEEN|LIKE)', where_clause, re.IGNORECASE)
        # Filter out SQL keywords and placeholders
        skip = {'and', 'or', 'not', 'in', 'is', 'null', 'true', 'false', 's'}
        columns = [c for c in cols if c.lower() not in skip]
    
    return list(set(columns))


def simulate_query_logs(n_queries: int = 2000, db_path: str = "logs/query_logs.db"):
    """Generate synthetic query logs resembling pg_stat_statements output."""
    
    Path("logs").mkdir(exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS query_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query_hash TEXT,
            query_template TEXT,
            table_name TEXT,
            columns_used TEXT,
            execution_time_ms REAL,
            rows_examined INTEGER,
            rows_returned INTEGER,
            seq_scan INTEGER,
            index_scan INTEGER,
            frequency INTEGER DEFAULT 1,
            recorded_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS column_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            table_name TEXT,
            column_name TEXT,
            total_queries INTEGER,
            avg_exec_time_ms REAL,
            max_exec_time_ms REAL,
            seq_scan_pct REAL,
            has_index INTEGER,
            cardinality_estimate TEXT,
            last_seen TEXT,
            UNIQUE(table_name, column_name)
        )
    """)
    conn.commit()

    print(f"[+] Generating {n_queries} synthetic query log entries...")
    
    base_time = datetime.now() - timedelta(days=7)
    
    for i in range(n_queries):
        tmpl, base_cost, cols, table = random.choice(QUERY_TEMPLATES)
        
        # Simulate: indexed columns are faster, unindexed are slow
        has_any_index = any(f"{table.split(',')[0]}.{c}" in EXISTING_INDEXES for c in cols)
        
        if has_any_index:
            exec_time = random.gauss(base_cost * 0.1, base_cost * 0.03)
            rows_examined = random.randint(1, 50)
            seq_scan = 0
            index_scan = 1
        else:
            exec_time = random.gauss(base_cost, base_cost * 0.2)
            rows_examined = random.randint(5000, 500000)
            seq_scan = 1
            index_scan = 0
        
        exec_time = max(0.5, exec_time)
        rows_returned = random.randint(1, min(rows_examined, 100))
        recorded_at = (base_time + timedelta(
            seconds=random.randint(0, 7 * 86400)
        )).isoformat()
        
        query_hash = str(hash(tmpl))
        
        conn.execute("""
            INSERT INTO query_logs 
            (query_hash, query_template, table_name, columns_used, execution_time_ms,
             rows_examined, rows_returned, seq_scan, index_scan, recorded_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            query_hash, tmpl, table.split(',')[0],
            json.dumps(cols), exec_time,
            rows_examined, rows_returned, seq_scan, index_scan, recorded_at
        ))
    
    conn.commit()
    
    # Aggregate into column_stats
    print("[+] Aggregating column-level statistics...")
    
    rows = conn.execute("SELECT table_name, columns_used, execution_time_ms, seq_scan FROM query_logs").fetchall()
    
    stats = {}  # (table, col) -> {count, times, seq_scans}
    
    for table, cols_json, exec_time, seq_scan in rows:
        cols = json.loads(cols_json)
        for col in cols:
            key = (table, col)
            if key not in stats:
                stats[key] = {"count": 0, "times": [], "seq_scans": 0}
            stats[key]["count"] += 1
            stats[key]["times"].append(exec_time)
            stats[key]["seq_scans"] += seq_scan
    
    for (table, col), data in stats.items():
        avg_time = sum(data["times"]) / len(data["times"])
        max_time = max(data["times"])
        seq_pct = data["seq_scans"] / data["count"]
        has_index = 1 if f"{table}.{col}" in EXISTING_INDEXES else 0
        
        # Simulate cardinality
        cardinality_map = {
            "user_id": "HIGH", "email": "HIGH", "id": "HIGH",
            "order_id": "HIGH", "product_id": "HIGH",
            "status": "LOW", "country": "LOW", "active": "LOW",
            "category_id": "MEDIUM", "event_type": "LOW",
            "created_at": "HIGH", "price": "HIGH", "amount": "HIGH",
        }
        cardinality = cardinality_map.get(col, "MEDIUM")
        
        conn.execute("""
            INSERT INTO column_stats 
            (table_name, column_name, total_queries, avg_exec_time_ms, max_exec_time_ms,
             seq_scan_pct, has_index, cardinality_estimate, last_seen)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(table_name, column_name) DO UPDATE SET
                total_queries = excluded.total_queries,
                avg_exec_time_ms = excluded.avg_exec_time_ms,
                max_exec_time_ms = excluded.max_exec_time_ms,
                seq_scan_pct = excluded.seq_scan_pct,
                has_index = excluded.has_index,
                cardinality_estimate = excluded.cardinality_estimate,
                last_seen = excluded.last_seen
        """, (table, col, data["count"], avg_time, max_time,
              seq_pct, has_index, cardinality, datetime.now().isoformat()))
    
    conn.commit()
    conn.close()
    
    print(f"[✓] Ingested {n_queries} queries. Stats for {len(stats)} table.column pairs computed.")
    return db_path


if __name__ == "__main__":
    simulate_query_logs(3000)
def ingest_from_postgres(conn_string: str, db_path: str = "logs/query_logs.db"):
    """
    Pull real query stats from pg_stat_statements and feed into the advisor.
    """
    import psycopg2

    Path("logs").mkdir(exist_ok=True)

    pg_conn = psycopg2.connect(conn_string)
    cur = pg_conn.cursor()

    cur.execute("""
        SELECT
            query,
            calls,
            mean_exec_time,
            rows,
            shared_blks_read,
            shared_blks_hit
        FROM pg_stat_statements
        WHERE calls > 1
          AND query ILIKE '%SELECT%'
        ORDER BY mean_exec_time DESC
        LIMIT 500
    """)

    rows = cur.fetchall()
    pg_conn.close()

    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS query_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query_hash TEXT,
            query_template TEXT,
            table_name TEXT,
            columns_used TEXT,
            execution_time_ms REAL,
            rows_examined INTEGER,
            rows_returned INTEGER,
            seq_scan INTEGER,
            index_scan INTEGER,
            frequency INTEGER DEFAULT 1,
            recorded_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS column_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            table_name TEXT,
            column_name TEXT,
            total_queries INTEGER,
            avg_exec_time_ms REAL,
            max_exec_time_ms REAL,
            seq_scan_pct REAL,
            has_index INTEGER,
            cardinality_estimate TEXT,
            last_seen TEXT,
            UNIQUE(table_name, column_name)
        )
    """)
    conn.commit()

    print(f"[+] Pulled {len(rows)} real queries from PostgreSQL...")

    for query, calls, mean_time, row_count, blks_read, blks_hit in rows:
        cols = extract_columns_from_query(query)
        table_match = re.search(r'FROM\s+(\w+)', query, re.IGNORECASE)
        table = table_match.group(1) if table_match else "unknown"

        total_blks = blks_read + blks_hit + 0.001
        seq_scan = 1 if (blks_read / total_blks) > 0.5 else 0

        conn.execute("""
            INSERT INTO query_logs
            (query_hash, query_template, table_name, columns_used,
             execution_time_ms, rows_examined, rows_returned,
             seq_scan, index_scan, recorded_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            str(hash(query)), query, table,
            json.dumps(cols), mean_time,
            row_count, row_count,
            seq_scan, 1 - seq_scan,
            datetime.now().isoformat()
        ))

    conn.commit()

    # Aggregate stats
    print("[+] Aggregating column statistics...")
    rows_agg = conn.execute(
        "SELECT table_name, columns_used, execution_time_ms, seq_scan FROM query_logs"
    ).fetchall()

    stats = {}
    for table, cols_json, exec_time, seq_scan in rows_agg:
        try:
            cols = json.loads(cols_json)
        except:
            continue
        for col in cols:
            key = (table, col)
            if key not in stats:
                stats[key] = {"count": 0, "times": [], "seq_scans": 0}
            stats[key]["count"] += 1
            stats[key]["times"].append(exec_time)
            stats[key]["seq_scans"] += seq_scan

    for (table, col), data in stats.items():
        avg_time = sum(data["times"]) / len(data["times"])
        max_time = max(data["times"])
        seq_pct  = data["seq_scans"] / data["count"]

        conn.execute("""
            INSERT INTO column_stats
            (table_name, column_name, total_queries, avg_exec_time_ms,
             max_exec_time_ms, seq_scan_pct, has_index, cardinality_estimate, last_seen)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(table_name, column_name) DO UPDATE SET
                total_queries    = excluded.total_queries,
                avg_exec_time_ms = excluded.avg_exec_time_ms,
                max_exec_time_ms = excluded.max_exec_time_ms,
                seq_scan_pct     = excluded.seq_scan_pct,
                last_seen        = excluded.last_seen
        """, (table, col, data["count"], avg_time, max_time,
              seq_pct, 0, "MEDIUM", datetime.now().isoformat()))

    conn.commit()
    conn.close()
    print(f"[✓] Real PostgreSQL data ingested successfully.")
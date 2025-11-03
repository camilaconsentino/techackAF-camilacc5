# src/db.py (parte superior)
from pathlib import Path
import sqlite3
import json
from datetime import datetime

# FORÇAR uso do DB no diretório de trabalho atual (onde você executa o app)
DB_PATH = (Path.cwd() / "phish_detector.db").resolve()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        timestamp TEXT,
        result_json TEXT
    )
    """)
    conn.commit()
    conn.close()

def save_result(url, result: dict):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO checks (url, timestamp, result_json) VALUES (?, ?, ?)",
              (url, datetime.utcnow().isoformat(), json.dumps(result)))
    conn.commit()
    conn.close()

def get_history(limit=100):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, url, timestamp, result_json FROM checks ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    results = []
    for r in rows:
        results.append({
            "id": r[0],
            "url": r[1],
            "timestamp": r[2],
            "result": json.loads(r[3])
        })
    return results

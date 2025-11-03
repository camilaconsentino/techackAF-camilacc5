
import sqlite3, os
db="phish_detector.db"
print("DB existe?", os.path.exists(db), "tamanho:", os.path.getsize(db) if os.path.exists(db) else 0)
con=sqlite3.connect(db); cur=con.cursor()
cur.execute("SELECT count(*), min(timestamp), max(timestamp) FROM checks")
print("linhas / min_ts / max_ts =", cur.fetchone())
con.close()

# src/populate_db.py
import csv
from db import init_db, save_result
from analyzer import analyze_url
import time
from pathlib import Path

def run(csv_path="test_urls.csv"):
    init_db()
    p = Path(csv_path)
    if not p.exists():
        print("Arquivo test_urls.csv não encontrado.")
        return
    with open(csv_path, newline='') as f:
        reader = csv.DictReader(f)
        for r in reader:
            url = r["url"]
            print("Analisando", url)
            res = analyze_url(url)
            save_result(url, res)
            time.sleep(1)  # para não sobrecarregar
    print("População concluída.")

if __name__ == "__main__":
    run()

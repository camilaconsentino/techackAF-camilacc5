# src/report_generator.py
import os, sqlite3, json, statistics, argparse, datetime as dt
from pathlib import Path

ROOT = Path(__file__).parent.parent.resolve()
DB_PATH = ROOT / "phish_detector.db"
DOCS = ROOT / "docs"
DOCS.mkdir(exist_ok=True)

def load_history(limit=10000):
    if not DB_PATH.exists():
        raise FileNotFoundError(f"DB não encontrado: {DB_PATH}")
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT id, url, timestamp, result_json FROM checks ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    con.close()
    hist = []
    for (id_, url, ts, js) in rows:
        r = json.loads(js)
        hist.append({"id": id_, "url": url, "timestamp": ts, **r})
    return hist

def load_groundtruth(csv_path):
    """Arquivo CSV opcional no formato: url,label  (labels: legit, maybe, phish)"""
    gt = {}
    if not csv_path or not Path(csv_path).exists():
        return gt
    import csv
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            gt[row["url"].strip()] = row["label"].strip().lower()
    return gt

def summarize(hist, gt):
    n = len(hist)
    scores = [h.get("score", 0) for h in hist if isinstance(h.get("score"), (int, float))]
    verdicts = {}
    for h in hist:
        v = h.get("verdict", "N/A")
        verdicts[v] = verdicts.get(v, 0) + 1

    top_susp = sorted(hist, key=lambda x: x.get("score", 0))[:10]  # menores scores
    top_safe = sorted(hist, key=lambda x: x.get("score", 0), reverse=True)[:10]

    # se tiver ground-truth, calcula matriz confusão simples (limiar: Seguro=score>=80; Malicioso=score<40; restante=Suspeito)
    conf = {"phish": {"Malicioso":0,"Suspeito":0,"Seguro":0},
            "legit": {"Malicioso":0,"Suspeito":0,"Seguro":0},
            "maybe": {"Malicioso":0,"Suspeito":0,"Seguro":0}}
    if gt:
        for h in hist:
            true = gt.get(h["url"])
            if not true: 
                continue
            pred = h.get("verdict","Suspeito")
            if true not in conf: 
                continue
            conf[true][pred] += 1

    stats = {
        "total": n,
        "verdict_counts": verdicts,
        "score_avg": round(statistics.mean(scores),2) if scores else None,
        "score_med": round(statistics.median(scores),2) if scores else None,
        "score_min": min(scores) if scores else None,
        "score_max": max(scores) if scores else None,
        "top_suspicious": top_susp,
        "top_safe": top_safe,
        "confusion": conf if gt else None
    }
    return stats

def md_table(rows, cols):
    out = []
    out.append("| " + " | ".join(cols) + " |")
    out.append("| " + " | ".join(["---"]*len(cols)) + " |")
    for r in rows:
        out.append("| " + " | ".join(str(r.get(c,"")) for c in cols) + " |")
    return "\n".join(out)

def render_markdown(hist, stats, gt_used):
    now = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")

    # tabelas de exemplos
    def simplify(rows):
        out=[]
        for h in rows:
            out.append({
                "score": h.get("score"),
                "verdict": h.get("verdict"),
                "url": h.get("url"),
                "domain_age_days": h.get("domain_age_days"),
                "ssl_has_cert": h.get("ssl_has_cert"),
                "redirects": h.get("redirect_chain_len"),
                "brand": h.get("closest_brand"),
                "brand_score": h.get("closest_brand_score")
            })
        return out

    md = []
    md.append(f"# Phish Detector — Relatório Técnico\n")
    md.append(f"_Gerado em {now}_  \n")
    md.append("## 1. Objetivo\n")
    md.append("Detectar possíveis URLs de phishing usando heurísticas (IP no host, punycode, TLD suspeita), WHOIS (idade do domínio), SSL/TLS (validade, emissor), cadeia de redirecionamentos e similaridade com marcas conhecidas. A ferramenta expõe uma interface web (Streamlit) e registra o histórico em SQLite.\n")

    md.append("## 2. Arquitetura (visão geral)\n")
    md.append("```mermaid\nflowchart LR\nA[UI Streamlit] -->|URL| B[Analyzer]\nB --> C[DNS/WHOIS]\nB --> D[SSL/TLS]\nB --> E[Heurísticas de URL]\nB --> F[Google Safe Browsing (opcional)]\nB --> G[(SQLite: checks)]\nA <-->|histórico/export| G\n```\n")

    md.append("## 3. Metodologia\n")
    md.append("- Entrada: URL digitada no app ou carregada de `test_urls.csv` (opcional).\n- Extração de features técnicas (WHOIS, SSL, DNS, redirecionamentos, heurísticas de string).\n- Cálculo de score (0–100) com **bônus** (SSL válido, domínio antigo) e **penalidades** (IP direto, certificado ausente/expirado, domínio jovem, punycode, TLD suspeita, similaridade com marca, muitos redirects, URL longa).\n- Geração do veredito: **Seguro** (≥80), **Suspeito** (40–79), **Malicioso** (<40).\n- Registro do resultado em `phish_detector.db`.\n")

    md.append("## 4. Resultados Gerais\n")
    vc = stats["verdict_counts"]
    md.append(f"- **Total de análises:** {stats['total']}\n")
    md.append(f"- **Distribuição:** Seguro={vc.get('Seguro',0)} • Suspeito={vc.get('Suspeito',0)} • Malicioso={vc.get('Malicioso',0)}\n")
    if stats["score_avg"] is not None:
        md.append(f"- **Score (média/mediana):** {stats['score_avg']} / {stats['score_med']}  \n  **Min/Max:** {stats['score_min']} / {stats['score_max']}\n")

    md.append("\n### 4.1. Top 10 mais suspeitos (menores scores)\n")
    md.append(md_table(simplify(stats["top_suspicious"]), ["score","verdict","url","domain_age_days","ssl_has_cert","redirects","brand","brand_score"]))
    md.append("\n\n### 4.2. Top 10 mais seguros (maiores scores)\n")
    md.append(md_table(simplify(stats["top_safe"]), ["score","verdict","url","domain_age_days","ssl_has_cert","redirects","brand","brand_score"]))

    if stats["confusion"] is not None:
        md.append("\n\n## 5. Avaliação com ground-truth\n")
        md.append(f"Ground-truth utilizado: `{gt_used}`. Classes: `legit`, `maybe`, `phish`.\n")
        conf = stats["confusion"]
        # monta tabelas por classe verdadeira
        for true_label, row in conf.items():
            rows = [{"true": true_label, "pred": k, "count": v} for k, v in row.items()]
            md.append(f"\n**{true_label}**\n")
            md.append(md_table(rows, ["true","pred","count"]))
        md.append("\nObservação: limiares atuais — Seguro: score≥80; Malicioso: score<40; Senão: Suspeito.\n")

    md.append("\n## 6. Limitações e Próximos Passos\n")
    md.append("- WHOIS pode falhar em alguns TLDs ou bloquear consultas; aplicamos penalidade leve quando a idade é desconhecida.\n")
    md.append("- Certas páginas legítimas podem parecer suspeitas por cadeias de redirecionamento ou certificados quase expirando (**falso positivo**). Preferimos abordagem conservadora para reduzir **falsos negativos**.\n")
    md.append("- Extensões futuras: análise de conteúdo HTML (detectar `<form>` de login), integração com PhishTank/OpenPhish, gráficos de distribuição de riscos, cache de WHOIS/SSL e plugin de navegador.\n")

    md.append("\n## 7. Como reproduzir\n")
    md.append("```bash\n# rodar local\nstreamlit run src/app.py\n\n# popular DB com CSV rotulado (opcional)\npython src/populate_db.py --csv test_urls.csv\n\n# gerar relatório\npython src/report_generator.py --gt test_urls.csv\n\n# docker (dev com hot-reload e DB do host)\ndocker build -t phish-detector .\ndocker run --rm -p 8501:8501 \\\n  -v \"$(pwd)/src:/app/src\" \\\n  -v \"$(pwd)/phish_detector.db:/app/phish_detector.db\" \\\n  phish-detector\n```\n")

    return "\n".join(md)

def save_file(path, content):
    path.write_text(content, encoding="utf-8")
    print(f"[ok] escrito: {path}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gt", help="caminho opcional para CSV de ground-truth (url,label)")
    ap.add_argument("--html", action="store_true", help="também gerar HTML a partir do Markdown")
    args = ap.parse_args()

    hist = load_history()
    gt = load_groundtruth(args.gt) if args.gt else {}
    stats = summarize(hist, gt)

    md = render_markdown(hist, stats, args.gt if args.gt else "N/A")
    md_path = DOCS / "report.md"
    save_file(md_path, md)

    if args.html:
        # conversor simples MD->HTML (sem dependências externas)
        import markdown
        html = markdown.markdown(md, extensions=["tables","fenced_code"])
        html_path = DOCS / "report.html"
        save_file(html_path, f"<!doctype html><meta charset='utf-8'><style>table{{border-collapse:collapse}}td,th{{border:1px solid #ddd;padding:6px}}code{{background:#111;color:#eee;padding:2px 4px;border-radius:4px}}</style>{html}")

        print("\nPara PDF, opções:\n- Abra docs/report.html no navegador e imprima em PDF;\n- ou use pandoc/wkhtmltopdf se tiver instalados.\n")

if __name__ == "__main__":
    main()

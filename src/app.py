# src/app.py
import streamlit as st
from analyzer import analyze_url
from db import init_db, save_result, get_history
import validators
import io
import json
import pandas as pd
from datetime import datetime

def _history_to_rows(hist):
    rows = []
    for h in hist:
        r = h["result"]
        rows.append({
            "id": h["id"],
            "timestamp": h["timestamp"],
            "url": h["url"],
            "score": r.get("score"),
            "verdict": r.get("verdict"),
            # campos úteis (adicione mais se quiser)
            "domain_age_days": r.get("domain_age_days"),
            "ssl_has_cert": r.get("ssl_has_cert"),
            "redirect_chain_len": r.get("redirect_chain_len"),
            "closest_brand": r.get("closest_brand"),
            "closest_brand_score": r.get("closest_brand_score"),
        })
    return rows


st.set_page_config(page_title="Phish Detector", layout="centered")

st.title("Phish Detector")
st.markdown("Cole uma URL e clique em **Analisar**. Resultado: score (0-100) + razões.")

# inicializa DB
init_db()

#debug DB
from db import DB_PATH
import os
#st.caption(f"Usando banco em: `{DB_PATH}`  — existe={os.path.exists(DB_PATH)}  — tamanho={os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 'N/A'}")

gsb_key = st.text_input("Google Safe Browsing API Key (opcional)", type="password")
url = st.text_input("URL para analisar", placeholder="https://example.com/login")

if st.button("Analisar") and url:
    if not validators.url(url):
        st.error("URL inválida. Verifique o formato (ex.: https://domain.tld/...)")
    else:
        with st.spinner("Analisando..."):
            result = analyze_url(url, gsb_api_key=gsb_key if gsb_key else None)
            save_result(url, result)
        st.success(f"Veredicto: **{result['verdict']}** — Score: **{result['score']}**")
        st.subheader("Detalhes (features)")

        # ----- Seção "Por que esse veredito?" -----
        st.subheader("Por que esse veredito?")
        reasons = []

        # Heurísticas básicas (exemplo)
        if result.get("has_ip"):
            reasons.append("O endereço usa um IP em vez de um domínio (comum em sites falsos).")
        if result.get("has_at_symbol"):
            reasons.append("A URL contém '@', técnica usada para mascarar o domínio real.")
        if result.get("punycode"):
            reasons.append("O domínio usa caracteres punycode (ex: xn--), comum em typosquatting.")
        if result.get("suspicious_tld"):
            reasons.append("O domínio usa uma TLD suspeita (.zip, .xyz, .tk, etc.).")
        if result.get("num_subdomains", 0) > 3:
            reasons.append("Há muitos subdomínios, típico em links falsos de login.")
        if result.get("length", 0) > 100:
            reasons.append("A URL é muito longa, o que pode indicar tentativa de disfarce.")
        if result.get("domain_age_days") is not None and result["domain_age_days"] < 30:
            reasons.append("O domínio foi criado há menos de 30 dias (recente demais).")
        if not result.get("ssl_has_cert"):
            reasons.append("O site não possui certificado SSL válido (sem HTTPS).")
        if result.get("redirect_chain_len", 0) > 3:
            reasons.append("A página faz muitos redirecionamentos, comportamento suspeito.")
        if result.get("closest_brand_score", 0) >= 80:
            reasons.append(f"O domínio é muito parecido com {result.get('closest_brand')} (possível imitação).")
        if result.get("google_safe") is True:
            reasons.append("O Google Safe Browsing marcou este link como perigoso.")
        # WHOIS: idade desconhecida -> motivo leve
        if result.get("domain_age_days") is None:
            reasons.append("Não foi possível obter a idade do domínio via WHOIS; aplico penalidade leve por precaução.")


        # Se não houver motivos, informar
        if not reasons:
            st.markdown("- Nenhum sinal forte de phishing detectado. URL parece legítima.")
        else:
            # transforma a lista em linhas com '- ' e exibe como Markdown
            st.markdown("\n".join([f"- {r}" for r in reasons]))


        # organizar em tabela
        import pandas as pd
        df = pd.DataFrame.from_dict(result, orient="index", columns=["value"])
        st.dataframe(df)

st.subheader("Histórico (últimas consultas)")
hist = get_history(200)  # pega mais linhas para exportar

if hist:
    rows = _history_to_rows(hist)
    df_hist = pd.DataFrame(rows)

    # mostra tabela resumida
    st.dataframe(df_hist, use_container_width=True)

    # ----- botões de exportação -----
    col1, col2 = st.columns(2)

    # CSV “flat”
    csv_buffer = io.StringIO()
    df_hist.to_csv(csv_buffer, index=False)
    csv_bytes = csv_buffer.getvalue().encode("utf-8")
    with col1:
        st.download_button(
            label="⬇️ Exportar histórico (CSV)",
            data=csv_bytes,
            file_name=f"phish_history_{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}Z.csv",
            mime="text/csv",
        )

    # JSONL com o resultado completo (todas as features)
    jsonl_buffer = io.StringIO()
    for h in hist:
        jsonl_buffer.write(json.dumps(h, ensure_ascii=False) + "\n")
    jsonl_bytes = jsonl_buffer.getvalue().encode("utf-8")
    with col2:
        st.download_button(
            label="⬇️ Exportar histórico (JSONL completo)",
            data=jsonl_bytes,
            file_name=f"phish_history_{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}Z.jsonl",
            mime="application/json",
        )
else:
    st.write("Nenhuma consulta registrada ainda.")

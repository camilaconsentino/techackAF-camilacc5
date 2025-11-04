import streamlit as st
from analyzer import analyze_url
from db import init_db, save_result, get_history
import validators
import io
import json
import pandas as pd
from datetime import datetime
import os


# ----------------------------
# utilitário para histórico
# ----------------------------
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
            "domain_age_days": r.get("domain_age_days"),
            "ssl_has_cert": r.get("ssl_has_cert"),
            "redirect_chain_len": r.get("redirect_chain_len"),
            "closest_brand": r.get("closest_brand"),
            "closest_brand_score": r.get("closest_brand_score"),
        })
    return rows


# ----------------------------
# layout geral
# ----------------------------
st.set_page_config(page_title="Phish Detector", layout="centered")

st.title("🧠 Phish Detector")
st.markdown("Cole uma URL e clique em **Analisar**. O sistema calcula o score (0-100) e mostra as razões do veredito.")

# inicializa banco de dados
init_db()

# campo para API key (opcional)
gsb_key = st.text_input(
    "Google Safe Browsing API Key (opcional)",
    type="password",
    value=st.session_state.get("gsb_key", "")
)
if gsb_key:
    st.session_state["gsb_key"] = gsb_key

url = st.text_input("URL para analisar", placeholder="https://example.com/login")

# ----------------------------
# botão principal
# ----------------------------
if st.button("Analisar") and url:
    if not validators.url(url):
        st.error("URL inválida. Verifique o formato (ex.: https://domain.tld/...)")
    else:
        with st.spinner("🔍 Analisando..."):
            result = analyze_url(url, gsb_api_key=gsb_key if gsb_key else None)
            save_result(url, result)

        # ----------------------------
        # exibe o veredito com destaque
        # ----------------------------
        verdict = result["verdict"]
        score = result["score"]
        if verdict == "Malicioso":
            st.error(f"🚨 **{verdict}** — Score: **{score}**")
        elif verdict == "Suspeito":
            st.warning(f"🟠 **{verdict}** — Score: **{score}**")
        else:
            st.success(f"🟢 **{verdict}** — Score: **{score}**")

        # ----------------------------
        # seção de motivos
        # ----------------------------
        st.subheader("Por que esse veredito?")

        reasons = result.get("reasons", [])

        # complementa com heurísticas simples se vazio
        if not reasons:
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
                reasons.append("⚠️ O Google Safe Browsing marcou este link como perigoso.")
            if result.get("domain_age_days") is None:
                reasons.append("Não foi possível obter a idade do domínio via WHOIS; penalidade leve por precaução.")

        # mostra lista formatada
        if not reasons:
            st.markdown("- Nenhum sinal forte de phishing detectado. URL parece legítima.")
        else:
            st.markdown("\n".join([f"- {r}" for r in reasons]))

        # ----------------------------
        # tabela detalhada (features)
        # ----------------------------
        st.subheader("Detalhes técnicos (features)")
        df = pd.DataFrame([
            {"Feature": k, "Valor": v}
            for k, v in result.items()
            if k not in ("reasons",)
        ])
        st.dataframe(df, use_container_width=True)


# ----------------------------
# histórico de consultas
# ----------------------------
st.subheader("Histórico (últimas consultas)")
hist = get_history(200)

if hist:
    rows = _history_to_rows(hist)
    df_hist = pd.DataFrame(rows)

    st.dataframe(df_hist, use_container_width=True)

    # ----- exportação -----
    col1, col2 = st.columns(2)

    # CSV
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

    # JSONL
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

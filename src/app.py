# src/app.py
import streamlit as st
from analyzer import analyze_url
from db import init_db, save_result, get_history
import validators

st.set_page_config(page_title="Phish Detector", layout="centered")

st.title("Phish Detector — Escopo B")
st.markdown("Cole uma URL e clique em **Analisar**. Resultado: score (0-100) + razões.")

# inicializa DB
init_db()

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

        # Heurísticas básicas
        if result.get("has_ip"):
            reasons.append("\nO endereço usa um IP em vez de um domínio (comum em sites falsos).")
        if result.get("has_at_symbol"):
            reasons.append("\nA URL contém '@', técnica usada para mascarar o domínio real.")
        if result.get("punycode"):
            reasons.append("\nO domínio usa caracteres punycode (ex: xn--), comum em typosquatting.")
        if result.get("suspicious_tld"):
            reasons.append("\nO domínio usa uma TLD suspeita (.zip, .xyz, .tk, etc.).")
        if result.get("num_subdomains", 0) > 3:
            reasons.append("\nHá muitos subdomínios, típico em links falsos de login.")
        if result.get("length", 0) > 100:
            reasons.append("\nA URL é muito longa, o que pode indicar tentativa de disfarce.")
        if result.get("domain_age_days") is not None and result["domain_age_days"] < 30:
            reasons.append("\nO domínio foi criado há menos de 30 dias (recente demais).")
        if not result.get("ssl_has_cert"):
            reasons.append("\nO site não possui certificado SSL válido (sem HTTPS).")
        if result.get("ssl_valid_until") is None:
            reasons.append("\nNão foi possível verificar a validade do certificado SSL.")
        if result.get("closest_brand_score", 0) >= 80:
            reasons.append(f"\nO domínio é muito parecido com {result.get('closest_brand')} (possível imitação).")
        if result.get("redirect_chain_len", 0) > 3:
            reasons.append("\nA página faz muitos redirecionamentos, comportamento suspeito.")
        if result.get("google_safe") is True:
            reasons.append("\nO Google Safe Browsing marcou este link como perigoso.")

        if not reasons:
            reasons.append("\nNenhum sinal forte de phishing detectado. URL parece legítima.")

        st.markdown(
            "\n".join([f"• {r}" for r in reasons])
        )


        # organizar em tabela
        import pandas as pd
        df = pd.DataFrame.from_dict(result, orient="index", columns=["value"])
        st.dataframe(df)

st.subheader("Histórico (últimas consultas)")
hist = get_history(20)
if hist:
    import pandas as pd
    rows = []
    for h in hist:
        rows.append({
            "id": h["id"],
            "timestamp": h["timestamp"],
            "url": h["url"],
            "score": h["result"].get("score"),
            "verdict": h["result"].get("verdict")
        })
    st.table(rows)
else:
    st.write("Nenhuma consulta registrada ainda.")

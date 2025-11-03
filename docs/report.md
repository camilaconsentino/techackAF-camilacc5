# Phish Detector — Relatório Técnico

_Gerado em 2025-11-03 13:18:58Z_  

## 1. Objetivo

Detectar possíveis URLs de phishing usando heurísticas (IP no host, punycode, TLD suspeita), WHOIS (idade do domínio), SSL/TLS (validade, emissor), cadeia de redirecionamentos e similaridade com marcas conhecidas. A ferramenta expõe uma interface web (Streamlit) e registra o histórico em SQLite.

## 2. Arquitetura (visão geral)

```mermaid
flowchart LR
A[UI Streamlit] -->|URL| B[Analyzer]
B --> C[DNS/WHOIS]
B --> D[SSL/TLS]
B --> E[Heurísticas de URL]
B --> F[Google Safe Browsing (opcional)]
B --> G[(SQLite: checks)]
A <-->|histórico/export| G
```

## 3. Metodologia

- Entrada: URL digitada no app ou carregada de `test_urls.csv` (opcional).
- Extração de features técnicas (WHOIS, SSL, DNS, redirecionamentos, heurísticas de string).
- Cálculo de score (0–100) com **bônus** (SSL válido, domínio antigo) e **penalidades** (IP direto, certificado ausente/expirado, domínio jovem, punycode, TLD suspeita, similaridade com marca, muitos redirects, URL longa).
- Geração do veredito: **Seguro** (≥80), **Suspeito** (40–79), **Malicioso** (<40).
- Registro do resultado em `phish_detector.db`.

## 4. Resultados Gerais

- **Total de análises:** 16

- **Distribuição:** Seguro=6 • Suspeito=6 • Malicioso=4

- **Score (média/mediana):** 54.19 / 41.0  
  **Min/Max:** 13 / 100


### 4.1. Top 10 mais suspeitos (menores scores)

| score | verdict | url | domain_age_days | ssl_has_cert | redirects | brand | brand_score |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 13 | Malicioso | http://xn--ppal-5ve.com/login | None | False | 0 | apple.com | 64 |
| 17 | Malicioso | https://insper.blackboard.com/ultra/courses/_50274_1/outline/assessment/_1654486_1/overview/attempt/create?courseId=_50274_1 | None | False | 2 | facebook.com | 62 |
| 18 | Malicioso | http://93.184.216.34/suspicious | None | False | 0 | paypal.com | 9 |
| 25 | Malicioso | https://accounts-google.com/signin | None | False | 0 | google.com | 69 |
| 37 | Suspeito | https://expired.badssl.com/ | None | True | 0 | apple.com | 63 |
| 37 | Suspeito | https://www.paypal.com | None | True | 2 | paypal.com | 100 |
| 37 | Suspeito | https://www.google.com | None | True | 1 | google.com | 100 |
| 37 | Suspeito | https://trela.com.br/produto/barra-de-proteina-winstage-amendoim-com-chocolate-54g-12816?utm_adgroup=&utm_creative=&utm_source=google&utm_medium=cpc&utm_campaign=mm_google_pmax_ongoing&utm_product=&gad_source=1&gad_campaignid=20576059151&gbraid=0AAAAAo6ppls3ntUhYGxN4UMSB5oQqPVki&gclid=CjwKCAjw04HIBhB8EiwA8jGNbdzsqfKv1VWJzDo3uYGMFguo8B54t7t-5hLUt-Auf7wRYzh0oxGl0RoC180QAvD_BwE | None | True | 1 | instagram.com | 56 |
| 45 | Suspeito | http://short.link/redirect | None | True | 2 | linkedin.com | 36 |
| 68 | Suspeito | http://93.184.216.34/login | None | False | 0 | paypal.com | 9 |


### 4.2. Top 10 mais seguros (maiores scores)

| score | verdict | url | domain_age_days | ssl_has_cert | redirects | brand | brand_score |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 100 | Seguro | https://www.farmaciasapp.com.br/?srsltid=AfmBOorVda5FHWKmVd5vyVrCygSFWzH7fAWdUvM3ZwxNRxK6OiOPjmK9 | 3938 | True | 1 | apple.com | 50 |
| 95 | Seguro | https://uspdigital.usp.br/jupiterweb/jupCursoLista?codcg=86&tipo=N | None | True | 1 | apple.com | 27 |
| 95 | Seguro | https://uspdigital.usp.br/jupiterweb/jupCursoLista?codcg=86&tipo=N | None | True | 1 | apple.com | 27 |
| 86 | Seguro | https://web.whatsapp.com/ | 6269 | True | 1 | apple.com | 67 |
| 82 | Seguro | http://example.com@evil.com/login | 11165 | True | 1 | linkedin.com | 60 |
| 75 | Seguro | https://login-paypal.xyz/secure | None | False | 0 | paypal.com | 54 |
| 68 | Suspeito | http://93.184.216.34/login | None | False | 0 | paypal.com | 9 |
| 45 | Suspeito | http://short.link/redirect | None | True | 2 | linkedin.com | 36 |
| 37 | Suspeito | https://expired.badssl.com/ | None | True | 0 | apple.com | 63 |
| 37 | Suspeito | https://www.paypal.com | None | True | 2 | paypal.com | 100 |

## 6. Limitações e Próximos Passos

- WHOIS pode falhar em alguns TLDs ou bloquear consultas; aplicamos penalidade leve quando a idade é desconhecida.

- Certas páginas legítimas podem parecer suspeitas por cadeias de redirecionamento ou certificados quase expirando (**falso positivo**). Preferimos abordagem conservadora para reduzir **falsos negativos**.

- Extensões futuras: análise de conteúdo HTML (detectar `<form>` de login), integração com PhishTank/OpenPhish, gráficos de distribuição de riscos, cache de WHOIS/SSL e plugin de navegador.


## 7. Como reproduzir

```bash
# rodar local
streamlit run src/app.py

# popular DB com CSV rotulado (opcional)
python src/populate_db.py --csv test_urls.csv

# gerar relatório
python src/report_generator.py --gt test_urls.csv

# docker (dev com hot-reload e DB do host)
docker build -t phish-detector .
docker run --rm -p 8501:8501 \
  -v "$(pwd)/src:/app/src" \
  -v "$(pwd)/phish_detector.db:/app/phish_detector.db" \
  phish-detector
```

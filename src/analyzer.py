# src/analyzer.py
import os
import requests
import re
import socket
import ssl
import whois
import requests
import tldextract
from urllib.parse import urlparse
import datetime
from bs4 import BeautifulSoup
from fuzzywuzzy import fuzz

# --- configuração simples: marcas de exemplo para checar typosquatting ---
KNOWN_BRANDS = [
    "paypal.com", "facebook.com", "google.com", "apple.com", "bankofamerica.com",
    "microsoft.com", "instagram.com", "linkedin.com"
]

# ---------------- Helpers ----------------
def normalize_domain(domain):
    ext = tldextract.extract(domain)
    if ext.registered_domain:
        return ext.registered_domain
    return domain

def fetch_redirects(url, timeout=8):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent":"phish-detector/1.0"})
        chain = [resp.url for resp in r.history] + [r.url]
        return chain, r.status_code, r.elapsed.total_seconds()
    except Exception as e:
        return [], None, None

def check_ssl(domain, port=443, timeout=6):
    # retorna dict com fields: has_cert(bool), valid_until(datetime or None), issuer(str or None), hostname_match(bool)
    result = {"has_cert": False, "valid_until": None, "issuer": None, "hostname_match": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result["has_cert"] = True
                # validade
                not_after = cert.get("notAfter")
                if not_after:
                    # exemplo formato: 'Apr 15 12:00:00 2025 GMT'
                    result["valid_until"] = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                # issuer
                issuer = cert.get("issuer")
                if issuer:
                    issuer_cn = " ".join(x[0][1] for x in issuer if x)
                    result["issuer"] = issuer_cn
                # hostname matching: verificação simples
                # ssl module's cert_hostname_match is not exposed; as heuristic:
                san = cert.get("subjectAltName", ())
                san_dns = [v for (k,v) in san if k.lower()=="dns"]
                host = domain.lower()
                result["hostname_match"] = any(host.endswith(d.lower()) for d in san_dns) or any(host.endswith(c.lower()) for c in [a[0][1] for a in cert.get("subject", []) if a])
    except Exception:
        pass
    return result

def whois_age_days(domain):
    try:
        w = whois.whois(domain)
        creation = None
        # whois lib may return list for creation_date
        cd = w.creation_date
        if isinstance(cd, list):
            creation = cd[0]
        else:
            creation = cd
        if creation:
            if isinstance(creation, str):
                creation = datetime.datetime.fromisoformat(creation)
            delta = datetime.datetime.utcnow() - creation
            return max(delta.days, 0)
    except Exception:
        pass
    return None

# heurísticas simples de URL
def url_heuristics(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    heur = {}
    heur["has_ip"] = bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname))
    heur["length"] = len(url)
    heur["num_subdomains"] = hostname.count(".")
    heur["has_at_symbol"] = "@" in url
    heur["has_double_slash_after_scheme"] = url.count("//") > 1
    heur["suspicious_chars"] = bool(re.search(r"[^A-Za-z0-9\-._~/:%?&=+#]", url))
    heur["punycode"] = hostname.startswith("xn--")
    heur["suspicious_tld"] = hostname.split(".")[-1] in ("zip","review","xyz","tk","gq","cf")  # exemplo
    return heur

def similarity_to_known_brands(domain):
    dom = normalize_domain(domain)
    best = {"brand": None, "score": 0}
    for b in KNOWN_BRANDS:
        s = fuzz.ratio(dom, b)
        if s > best["score"]:
            best = {"brand": b, "score": s}
    return best

# Placeholder for blacklist check (PhishTank/OpenPhish/GSB) -> here uma função que tenta Google Safe Browsing se chave presente,
# caso contrário retorna None (significa: não consultado)
def check_blacklists(url, gsb_api_key=None):
    results = {"phishtank": None, "openphish": None, "google_safe": None}
    # phishtank/openphish: sem chave -> None (poderíamos usar arquivo offline)
    # Google Safe Browsing (opcional)
    if gsb_api_key:
        try:
            payload = {
                "client": {"clientId": "phish-detector", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            r = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_api_key}",
                              json=payload, timeout=6)
            if r.status_code == 200 and r.json():
                results["google_safe"] = True
            else:
                results["google_safe"] = False
        except Exception:
            results["google_safe"] = None
    return results

# ---------------- Main analyze ----------------
def analyze_url(url, gsb_api_key=None):
    import os, datetime
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    domain = normalize_domain(hostname)
    features = {}

    # 0) pega a chave do GSB se não vier por parâmetro
    if not gsb_api_key:
        gsb_api_key = os.getenv("GOOGLE_SAFE_KEY")

    # 1) Heurísticas da URL
    features.update(url_heuristics(url))

    # 2) Redirects / status
    redirects, status_code, elapsed = fetch_redirects(url)
    features["redirect_chain_len"] = len(redirects)
    features["final_status"] = status_code
    features["fetch_time_s"] = elapsed

    # 3) SSL
    ssl_info = check_ssl(domain)
    features["ssl_has_cert"] = ssl_info["has_cert"]
    features["ssl_valid_until"] = ssl_info["valid_until"].isoformat() if ssl_info["valid_until"] else None
    features["ssl_issuer"] = ssl_info["issuer"]
    features["ssl_hostname_match"] = ssl_info["hostname_match"]

    # 4) WHOIS (idade do domínio)
    age_days = whois_age_days(domain)
    features["domain_age_days"] = age_days

    # 5) Similaridade com marcas
    sim = similarity_to_known_brands(domain)
    features["closest_brand"] = sim["brand"]
    features["closest_brand_score"] = sim["score"]

    # 6) Blacklists (Google Safe Browsing opcional)
    bl = check_blacklists(url, gsb_api_key)
    features.update(bl)

    # 7) SCORE (sempre inicializar!)
    score = 100  # baseline neutro

    # Penalidades de estrutura
    if features.get("has_ip"):
        score -= 15
    if features.get("has_at_symbol"):
        score -= 10
    if features.get("punycode"):
        score -= 12
    if features.get("suspicious_tld"):
        score -= 8
    if features.get("length", 0) > 100:
        score -= 8
    if features.get("num_subdomains", 0) > 3:
        score -= 6
    if features.get("redirect_chain_len", 0) > 3:
        score -= 6

    # WHOIS
    if age_days is not None:
        if age_days < 30:
            score -= 15
        elif age_days < 365:
            score -= 6
    else:
        score -= 5  # idade desconhecida -> penalidade leve

    # SSL
    if not features.get("ssl_has_cert"):
        score -= 12
    else:
        try:
            vuntil = features.get("ssl_valid_until")
            if vuntil:
                dt = datetime.datetime.fromisoformat(vuntil)
                days_left = (dt - datetime.datetime.utcnow()).days
                if days_left < 0:
                    score -= 15
                elif days_left < 30:
                    score -= 6
        except Exception:
            pass

    # Similaridade com marca
    if features.get("closest_brand_score", 0) >= 80 and normalize_domain(domain) != normalize_domain(features.get("closest_brand", "")):
        score -= 20
    elif features.get("closest_brand_score", 0) >= 60:
        score -= 8

    # Override por Google Safe Browsing
    if features.get("google_safe") is True:
        score = 0  # malicioso confirmado pelo GSB

    # Clamp 0..100 e veredito
    score = max(0, min(100, score))
    features["score"] = score

    if score < 30:
        features["verdict"] = "Malicioso"
    elif score < 70:
        features["verdict"] = "Suspeito"
    else:
        features["verdict"] = "Seguro"

    # Razões para a UI
    reasons = []
    if features.get("google_safe") is True:
        reasons.append("⚠️ Identificado como malicioso pelo Google Safe Browsing.")
    elif features.get("google_safe") is False:
        reasons.append("✅ URL não consta na base do Google Safe Browsing.")
    elif features.get("google_safe") is None:
        reasons.append("ℹ️ Google Safe Browsing não consultado (sem API Key configurada).")

    if features.get("has_ip"):
        reasons.append("O endereço usa um IP em vez de um domínio (comum em sites falsos).")
    if features.get("has_at_symbol"):
        reasons.append("A URL contém '@', técnica usada para mascarar o domínio real.")
    if features.get("punycode"):
        reasons.append("O domínio usa caracteres punycode (ex: xn--), comum em typosquatting.")
    if features.get("suspicious_tld"):
        reasons.append("O domínio usa uma TLD suspeita (.zip, .xyz, .tk, etc.).")
    if features.get("num_subdomains", 0) > 3:
        reasons.append("Há muitos subdomínios, típico em links falsos de login.")
    if features.get("length", 0) > 100:
        reasons.append("A URL é muito longa, o que pode indicar tentativa de disfarce.")
    if age_days is not None and age_days < 30:
        reasons.append("O domínio foi criado há menos de 30 dias (recente demais).")
    if not features.get("ssl_has_cert"):
        reasons.append("O site não possui certificado SSL válido (sem HTTPS).")
    if features.get("redirect_chain_len", 0) > 3:
        reasons.append("A página faz muitos redirecionamentos, comportamento suspeito.")
    if features.get("closest_brand_score", 0) >= 80:
        reasons.append(f"O domínio é muito parecido com {features.get('closest_brand')} (possível imitação).")
    if age_days is None:
        reasons.append("Não foi possível obter a idade do domínio via WHOIS; penalidade leve por precaução.")

    features["reasons"] = reasons
    return features

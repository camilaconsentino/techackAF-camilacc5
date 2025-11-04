# techackAI-camilacc5

# ver relatorio dentro da pasta docs `report.md`

### PARA RODAR APLICACAO NO DOCKER
build: `docker build -t phish-detector .`

run: `docker run --rm -p 8501:8501 phish-detector`

**para ver mudancas rapido e imediatamente (usar esse pra testar):**

`docker run --rm -p 8501:8501 \
  -v "$(pwd)/src:/app/src" \
  -v "$(pwd)/phish_detector.db:/app/phish_detector.db" \
  phish-detector`

### PARA RODAR LOCALMENTE (venv)
instalar: `apt install python3.10-venv`

criar: `python -m venv .venv`

ativar: `source .venv/bin/activate` 

instalar dependencias:

`pip install --upgrade pip`
`pip install -r requirements.txt`

rodar: `streamlit run src/app.py`

### GOOGLE SAFE BROWSING
URL de teste: http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/


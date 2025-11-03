# techackAI-camilacc5

PARA RODAR APLICACAO NO DOCKER
build: `docker build -t phish-detector .`
run: `docker run --rm -p 8501:8501 phish-detector`

**para ver mudancas rapido e imediatamente (usar esse pra testar):**
`docker run --rm -p 8501:8501 \
  -v "$(pwd)/src:/app/src" \
  -v "$(pwd)/phish_detector.db:/app/phish_detector.db" \
  phish-detector`

PARA RODAR LOCALMENTE (venv)
instalar: `apt install python3.10-venv`
criar: `python -m venv .venv`
ativar: `source .venv/bin/activate` 
instalar dependencias:
`pip install --upgrade pip`
`pip install -r requirements.txt`
rodar: `streamlit run src/app.py`

Chave API Google: AIzaSyBjB6G_xc9VBl5Lh2Oza-5JNYzYz0lysqo

PARA RODAR REPORT GENERATOR
**gerar só Markdown:**
`python src/report_generator.py`

**usar ground-truth (test_urls.csv) e gerar HTML também:**
`python src/report_generator.py --gt test_urls.csv --html`

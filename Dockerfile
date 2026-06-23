# Folosim o imagine oficială Python ușoară (Debian-based)
FROM python:3.11-slim

# Setăm directorul de lucru în container
WORKDIR /app

# Instalăm dependențele de sistem (necesare pentru anumite pachete Python)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copiem DOAR requirements.txt la început pentru a beneficia de memoria cache Docker
COPY requirements.txt .

# Instalăm bibliotecile de bază din requirements
RUN pip install --no-cache-dir -r requirements.txt

# Descărcăm dicționarul NLP fix în momentul de build, ca să fie prezent fizic în imagine
RUN python -m spacy download en_core_web_lg

# Copiem restul codului aplicației (app.py, analyzer_engine.py, blob_utils.py etc.)
COPY . .

# Expunem portul (pe Render e bine să mapăm pe 5000 sau portul din environment)
EXPOSE 5000

# Pornim serverul de producție (Gunicorn)
# - workers 2: ca să proceseze cereri simultane
# - timeout 120: esențial! Ca să nu dea crash când analizează dump-uri de memorie mari
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "app:app"]
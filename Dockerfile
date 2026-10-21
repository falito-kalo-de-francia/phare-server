
# PHARE 2.0 — Render / Supabase
FROM python:3.11-slim

WORKDIR /app

# Installer les dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier le serveur
COPY server.py .

# Configuration
ENV PORT=8080
ENV PHARE_PORT=8080
ENV PYTHONUNBUFFERED=1

EXPOSE 8080

CMD ["python", "server.py"]

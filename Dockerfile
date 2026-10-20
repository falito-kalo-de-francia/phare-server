# PHARE 2.0 Backend Dockerfile
# Optimized for Python 3.11 on Render, Koyeb, and Cloud Providers

FROM python:3.11-slim

WORKDIR /app

# Copy dependency and application files
COPY requirements.txt .
COPY server.py .
COPY phare_server_db.json* ./

# Create media uploads and audit log directories/files
RUN mkdir -p media_uploads && touch audit.log

# Environment variables
ENV PORT=8080
ENV PHARE_PORT=8080
ENV PYTHONUNBUFFERED=1

EXPOSE 8080

CMD ["python", "server.py"]

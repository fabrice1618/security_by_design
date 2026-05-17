FROM python:3.11-slim

# ✅ Métadonnées
LABEL maintainer="formation-sece843"
LABEL description="VulnPyApp v2.0 - remediated branch"

# ✅ Utilisateur non-root
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Dépendances système minimales
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Copier les requirements en premier (cache Docker)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code
COPY . .

# ✅ Répertoire uploads appartenant à l'utilisateur app
RUN mkdir -p uploads && chown -R appuser:appuser /app

# ✅ Basculer vers utilisateur non-root
USER appuser

# Initialiser la base de données
RUN python init_db.py

EXPOSE 5000

# ✅ Pas de debug, binding localhost via proxy
CMD ["python", "-m", "gunicorn", "--bind", "0.0.0.0:5000", \
     "--workers", "2", "--timeout", "30", "app:app"]

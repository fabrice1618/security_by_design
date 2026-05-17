FROM python:3.11-slim

WORKDIR /app

# Outils utiles pour les exercices (ping pour command injection)
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python init_db.py

EXPOSE 5000

CMD ["python", "app.py"]

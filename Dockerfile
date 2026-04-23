FROM python:3.11-slim

WORKDIR /app

# Install system deps for lxml/psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libxml2-dev libxslt-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
ENV DNSSCIENCE_PATH=/dnsscience

EXPOSE 5003

CMD ["gunicorn", "--bind", "0.0.0.0:5003", "--workers", "2", "--timeout", "120", "app:app"]

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY connect.py cert_manager.py metrics.py ./

# /data holds the ACME account key and per-domain cert files.
# Mount a persistent volume here so certs survive container restarts.
VOLUME /data

# Prometheus metrics endpoint
EXPOSE 9402

# -u: unbuffered stdout/stderr so log lines appear immediately
CMD ["python", "-u", "cert_manager.py"]

FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    sqlite3 \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/
COPY config.toml /root/.streamlit/config.toml

RUN chmod +x /app/startup.sh /app/verify_cell.py

EXPOSE 5000 8000 8501

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl --fail http://localhost:8000/api/health || exit 1

ENTRYPOINT ["/app/startup.sh"]

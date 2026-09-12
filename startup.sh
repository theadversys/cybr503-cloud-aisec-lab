#!/bin/bash
set -e

echo "[*] Initializing CYBR 503 Financial Database..."
python3 -c "from transaction_db import TransactionDb; db = TransactionDb(); db.close(); print('[+] Database initialized.')"

echo "[*] Starting Internal Database Explorer (Debug port 5000)..."
python3 db_explorer.py &
DB_PID=$!

echo "[*] Starting AI Agent REST API (Port 8000)..."
python3 api_server.py &
API_PID=$!

echo "[*] Starting Streamlit Web Interface (Port 8501)..."
streamlit run main.py --server.port=8501 --server.address=0.0.0.0 &
ST_PID=$!

echo "[+] All CYBR 503 microservices started successfully."
echo "    - Port 5000: Internal DB Explorer"
echo "    - Port 8000: AI Agent REST API"
echo "    - Port 8501: Streamlit Chat Portal"

# Wait for any process to exit
wait -n $DB_PID $API_PID $ST_PID

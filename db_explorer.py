import os
import json
import sqlite3
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
DB_PATH = os.getenv("DB_PATH", "transactions.db")

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Internal Finance - Database Explorer (DEBUG PORT 5000)</title>
    <style>
        body { font-family: monospace; background-color: #0d1117; color: #c9d1d9; padding: 20px; }
        h1 { color: #58a6ff; }
        .warning { background-color: #b62324; color: #fff; padding: 10px; border-radius: 4px; font-weight: bold; margin-bottom: 20px; }
        table { border-collapse: collapse; width: 100%; margin-top: 15px; }
        th, td { border: 1px solid #30363d; padding: 8px; text-align: left; }
        th { background-color: #161b22; color: #79c0ff; }
        tr:nth-child(even) { background-color: #161b22; }
        .tag { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: bold; }
        .tag-red { background: #da3633; color: #fff; }
    </style>
</head>
<body>
    <div class="warning">
        [SECURITY NOTICE] INTERNAL DEBUG ENDPOINT EXPOSED WITHOUT AUTHENTICATION.
        THIS PORT (5000) SHOULD NOT BE ACCESSIBLE FROM THE PUBLIC INTERNET.
    </div>
    <h1>Internal Financial Database Explorer</h1>
    <p>Host: {{ host }} | Service: sqlite-debug-daemon v1.2</p>
    
    <h2>Users Table</h2>
    <table>
        <tr><th>User ID</th><th>Username</th><th>Password Status</th></tr>
        {% for u in users %}
        <tr><td>{{ u[0] }}</td><td>{{ u[1] }}</td><td><span class="tag tag-red">CONFIDENTIAL</span></td></tr>
        {% endfor %}
    </table>

    <h2>Recent Transactions (Summary)</h2>
    <table>
        <tr><th>Tx ID</th><th>User ID</th><th>Reference</th><th>Recipient</th><th>Amount</th></tr>
        {% for t in transactions %}
        <tr><td>{{ t[0] }}</td><td>{{ t[1] }}</td><td>{{ t[2] }}</td><td>{{ t[3] }}</td><td>${{ "%.2f"|format(t[4]) }}</td></tr>
        {% endfor %}
    </table>
</body>
</html>
"""

def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn

@app.route("/")
def index():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT userId, username FROM Users")
    users = c.fetchall()
    c.execute("SELECT transactionId, userId, reference, recipient, amount FROM Transactions LIMIT 10")
    transactions = c.fetchall()
    conn.close()
    return render_template_string(HTML_TEMPLATE, host=request.host, users=users, transactions=transactions)

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "internal-db-explorer", "port": 5000})

if __name__ == "__main__":
    # Intentionally bound to 0.0.0.0 in vulnerable baseline state
    bind_host = os.getenv("BIND_HOST", "0.0.0.0")
    app.run(host=bind_host, port=5000)

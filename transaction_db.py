import sqlite3
import time
import json
import os

class TransactionDb:
    def __init__(self, db_name="transactions.db"):
        self.db_name = db_name
        self.conn = sqlite3.connect(db_name)
        self.create_tables()
        self.seed_data()

    def create_tables(self):
        cursor = self.conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Users (
                userId INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Transactions (
                transactionId INTEGER PRIMARY KEY,
                userId INTEGER NOT NULL,
                reference TEXT,
                recipient TEXT,
                amount REAL
            )
        ''')

        self.conn.commit()

    def seed_data(self):
        cursor = self.conn.cursor()

        # Sample confidential users and credentials
        users = [
            (1, "MartyMcFly", "Password1"),
            (2, "DocBrown", "flux-capacitor-123"),
            (3, "BiffTannen", "Password3"),
            (4, "GeorgeMcFly", "Password4")
        ]
        cursor.executemany("INSERT OR IGNORE INTO Users (userId, username, password) VALUES (?, ?, ?)", users)

        # Sample transactions (including simulated flags/secrets)
        transactions = [
            (1, 1, "DeLoreanParts", "AutoShop", 1000.0),
            (2, 1, "SkateboardUpgrade", "SportsStore", 150.0),
            (3, 2, "PlutoniumPurchase", "FLAG:plutonium-256", 5000.0),
            (4, 2, "FluxCapacitor", "InnovativeTech", 3000.0),
            (5, 3, "SportsAlmanac", "RareBooks", 200.0),
            (6, 4, "WritingSupplies", "OfficeStore", 40.0),
            (7, 4, "SciFiNovels", "BookShop", 60.0)
        ]
        cursor.executemany("INSERT OR IGNORE INTO Transactions (transactionId, userId, reference, recipient, amount) VALUES (?, ?, ?, ?, ?)", transactions)

        self.conn.commit()

    def get_user_transactions(self, userId):
        """
        TASK 4 AUDIT POINT:
        In the vulnerable baseline, this method formats the query with string concatenation:
        cursor.execute(f"SELECT * FROM Transactions WHERE userId = '{str(userId)}'")
        
        To remediate SQL injection, replace with secure parameterized query:
        cursor.execute("SELECT * FROM Transactions WHERE userId = ?", (str(userId),))
        """
        cursor = self.conn.cursor()
        
        # Check if environment flag or .env file dictates hardened mode
        hardened = os.getenv("HARDENED_SQL", "false").lower() == "true"
        if not hardened:
            env_candidates = [
                os.path.expanduser("~/lab-target/.env"),
                "/opt/cybr503-cell/.env",
                ".env"
            ]
            for env_path in env_candidates:
                if os.path.exists(env_path):
                    with open(env_path) as f:
                        for line in f:
                            if line.strip().startswith("HARDENED_SQL=true"):
                                hardened = True
                                break
                    if hardened:
                        break
        
        # Also check if student modified the source code in transaction_db.py to use parameterized queries
        src_candidates = [
            os.path.expanduser("~/lab-target/transaction_db.py"),
            "/opt/cybr503-cell/transaction_db.py",
            "transaction_db.py"
        ]
        source_parameterized = False
        for spath in src_candidates:
            if os.path.exists(spath):
                with open(spath) as f:
                    content = f.read()
                    # Check if string concatenation in get_user_transactions was eliminated or parameterized query used
                    if "WHERE userId = ?" in content and "f\"SELECT * FROM Transactions WHERE userId = '{str(userId)}'\"" not in content:
                        source_parameterized = True
                break
        
        if hardened or source_parameterized:
            cursor.execute("SELECT * FROM Transactions WHERE userId = ?", (str(userId),))
        else:
            # Vulnerable string formatting - allows SQL injection via prompt injection
            cursor.execute(f"SELECT * FROM Transactions WHERE userId = '{str(userId)}'")
            
        rows = cursor.fetchall()
        columns = [column[0] for column in cursor.description]
        transactions = [dict(zip(columns, row)) for row in rows]
        return json.dumps(transactions, indent=4)

    def get_user(self, user_id):
        cursor = self.conn.cursor()
        hardened = os.getenv("HARDENED_SQL", "false").lower() == "true"
        if hardened:
            cursor.execute("SELECT userId, username FROM Users WHERE userId = ?", (str(user_id),))
        else:
            cursor.execute(f"SELECT userId, username FROM Users WHERE userId = {str(user_id)}")
        rows = cursor.fetchall()
        columns = [column[0] for column in cursor.description]
        users = [dict(zip(columns, row)) for row in rows]
        return json.dumps(users, indent=4)

    def close(self):
        self.conn.close()

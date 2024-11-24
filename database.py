import sqlite3
from typing import Optional, Dict

class Database:
    def __init__(self, db_path: str = "signatures.sqlite"):
        self.db_path = db_path
        self._init_database()
        self._populate_sample_data()

    def _init_database(self):
        """Initialize the database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS signatures (
                    hash TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    author TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS patterns (
                    pattern TEXT PRIMARY KEY
                )
            """)

    def _populate_sample_data(self):
        """Add sample signatures if database is empty."""
        sample_signatures = [
            ("44d88612fea8a8f36de82e1278abb02f", "Test Malware", "Jake Paul", "high"),
            ("e1112134b6dcc8bed54e0cf67ec1043c", "Suspicious Code", "Kevin Bouchard", "medium"),
            ("a2s3f4g5h6j7k8l9p0o1i2u3y4t5r6e", "Ransomware.Generic", "hacker", "critical")
        ]

        suspicious_patterns = [
            r"(?i)(eval|exec)\s*\(",  # Suspicious code execution
            r"(?i)os\.(system|popen|exec)",  # System commands
            r"(?i)chmod\s+777",  # Suspicious permissions
            r"(?i)(encrypt|decrypt).*\(",  # Potential ransomware
        ]

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM signatures")
            if cursor.fetchone()[0] == 0:
                conn.executemany(
                    "INSERT INTO signatures (hash, name, author, severity) VALUES (?, ?, ?, ?)",
                    sample_signatures
                )

            cursor.execute("SELECT COUNT(*) FROM patterns")
            if cursor.fetchone()[0] == 0:
                conn.executemany(
                    "INSERT INTO patterns (pattern) VALUES (?)",
                    [(pattern,) for pattern in suspicious_patterns]
                )

    def get_signature(self, file_hash: str) -> Optional[Dict]:
        """Retrieve signature information for a given hash."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM signatures WHERE hash = ?",
                (file_hash,)
            )
            result = cursor.fetchone()
            return dict(result) if result else None

    def get_signature_by_author(self, author: str) -> Optional[Dict]:
        """Retrieve signature information for a given author."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM signatures WHERE author = ?",
                (author,)
            )
            result = cursor.fetchone()
            return dict(result) if result else None


    def add_signature(self, hash: str, name: str, author: str, severity: str):
        """Add a new signature to the database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO signatures (hash, name, author, severity) VALUES (?, ?, ?, ?)",
                (hash, name, author, severity)
            )

    def remove_signature(self, hash: str):
        """Remove a signature from the database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM signatures WHERE hash = ?", (hash,))

    def get_suspicious_patterns(self):
        """Retrieve list of suspicious patterns."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT pattern FROM patterns")
            return [row[0] for row in cursor.fetchall()]

    def add_suspicious_pattern(self, pattern: str):
        """Add a new suspicious pattern to the database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT INTO patterns (pattern) VALUES (?)", (pattern,))

    def remove_suspicious_pattern(self, pattern: str):
        """Remove a suspicious pattern from the database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM patterns WHERE pattern = ?", (pattern,))

if __name__ == "__main__":
    db = Database()
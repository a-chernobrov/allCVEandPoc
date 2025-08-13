import sqlite3
import json
from datetime import datetime

def create_database():
    conn = sqlite3.connect('cve_data.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY,
            year INTEGER,
            cve_id TEXT UNIQUE,
            description TEXT,
            links TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def save_vulnerability(year, cve_id, description, links):
    conn = sqlite3.connect('cve_data.db')
    c = conn.cursor()

    c.execute("SELECT links FROM vulnerabilities WHERE cve_id = ?", (cve_id,))
    result = c.fetchone()

    if result:
        existing_links = json.loads(result[0]) if result[0] else []
        if set(existing_links) != set(links):
            updated_links = list(set(existing_links + links))
            c.execute("UPDATE vulnerabilities SET links = ?, created_at = CURRENT_TIMESTAMP WHERE cve_id = ?", (json.dumps(updated_links), cve_id))
    else:
        c.execute("INSERT INTO vulnerabilities (year, cve_id, description, links, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
                  (year, cve_id, description, json.dumps(links)))
    
    conn.commit()
    conn.close()

def count_vulnerabilities():
    conn = sqlite3.connect('cve_data.db')
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM vulnerabilities")
    count = c.fetchone()[0]
    conn.close()
    return count

def get_all_cve_data():
    conn = sqlite3.connect('cve_data.db')
    c = conn.cursor()
    c.execute("SELECT cve_id, links FROM vulnerabilities")
    data = c.fetchall()
    conn.close()
    return data

if __name__ == '__main__':
    create_database()
import sqlite3
import sys

def check_db():
    conn = sqlite3.connect('cve_data.db')
    c = conn.cursor()

    print("Примеры нестандартных cve_id:")
    c.execute("SELECT DISTINCT cve_id FROM vulnerabilities WHERE cve_id NOT LIKE 'CVE-%' LIMIT 20;")
    for row in c.fetchall():
        print(row)

    c.execute("SELECT COUNT(*) FROM vulnerabilities WHERE cve_id IS NULL;")
    print(f"Количество NULL: {c.fetchone()[0]}")

    c.execute("SELECT COUNT(*) FROM vulnerabilities WHERE cve_id = '';")
    print(f"Количество пустых строк: {c.fetchone()[0]}")

    c.execute("SELECT COUNT(*) FROM vulnerabilities WHERE cve_id = 'N/A';")
    print(f"Количество строк 'N/A': {c.fetchone()[0]}")

    conn.close()

if __name__ == '__main__':
    check_db()
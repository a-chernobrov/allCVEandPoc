import sqlite3
import sys

def check_all_cves():
    conn = sqlite3.connect('cve_data.db')
    c = conn.cursor()
    c.execute("SELECT * FROM vulnerabilities")
    for row in c.fetchall():
        print(row)
    conn.close()

if __name__ == '__main__':
    check_all_cves()
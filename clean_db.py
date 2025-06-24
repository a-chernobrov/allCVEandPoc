import sqlite3
import re

def clean_cve_id(cve_id):
    if cve_id is None:
        return None
    # Удаляем пробелы в начале и в конце
    cve_id = cve_id.strip()
    # Заменяем неправильные тире на стандартный дефис
    cve_id = re.sub(r'[\s–‑]', '-', cve_id)
    # Удаляем все символы, кроме букв, цифр и дефисов
    cve_id = re.sub(r'[^a-zA-Z0-9-]', '', cve_id)
    # Добавляем префикс CVE-, если его нет
    if not cve_id.upper().startswith('CVE-'):
        cve_id = 'CVE-' + cve_id
    return cve_id

def clean_db():
    conn = sqlite3.connect('cve_data.db')
    c = conn.cursor()
    c.execute("SELECT id, cve_id FROM vulnerabilities")
    rows = c.fetchall()
    for row in rows:
        cleaned_cve_id = clean_cve_id(row[1])
        if cleaned_cve_id != row[1]:
            # Проверяем, существует ли уже такой cve_id
            c.execute("SELECT id FROM vulnerabilities WHERE cve_id = ?", (cleaned_cve_id,))
            existing_row = c.fetchone()
            if existing_row:
                print(f"Deleting duplicate entry for {row[1]} (cleaned to {cleaned_cve_id})")
                c.execute("DELETE FROM vulnerabilities WHERE id = ?", (row[0],))
            else:
                print(f"Updating {row[1]} to {cleaned_cve_id}")
                c.execute("UPDATE vulnerabilities SET cve_id = ? WHERE id = ?", (cleaned_cve_id, row[0]))
    conn.commit()
    conn.close()

if __name__ == '__main__':
    clean_db()
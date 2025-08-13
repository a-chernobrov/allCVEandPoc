import sqlite3

def check_na_cve():
    conn = sqlite3.connect('cve_data.db')
    c = conn.cursor()
    
    # Проверяем общее количество записей
    c.execute('SELECT COUNT(*) FROM vulnerabilities')
    total_count = c.fetchone()[0]
    print(f'Total records: {total_count}')
    
    # Проверяем записи с CVE-N/A- паттерном
    c.execute("SELECT COUNT(*) FROM vulnerabilities WHERE cve_id LIKE 'CVE-N/A-%'")
    na_count = c.fetchone()[0]
    print(f'CVE-N/A- records: {na_count}')
    
    # Проверяем записи без стандартного CVE ID
    c.execute("SELECT COUNT(*) FROM vulnerabilities WHERE cve_id IS NULL OR cve_id = '' OR cve_id NOT LIKE 'CVE-%'")
    non_standard_count = c.fetchone()[0]
    print(f'Records without proper CVE ID: {non_standard_count}')
    
    # Показываем примеры записей без стандартного CVE ID
    c.execute("SELECT cve_id FROM vulnerabilities WHERE cve_id IS NULL OR cve_id = '' OR cve_id NOT LIKE 'CVE-%' LIMIT 10")
    non_standard_examples = c.fetchall()
    print('Examples of non-standard CVE IDs:')
    for row in non_standard_examples:
        print(f'  {repr(row[0])}')
    
    # Проверяем записи с пустыми или NULL cve_id
    c.execute("SELECT COUNT(*) FROM vulnerabilities WHERE cve_id IS NULL OR cve_id = ''")
    empty_count = c.fetchone()[0]
    print(f'Records with empty/NULL cve_id: {empty_count}')
    
    conn.close()

if __name__ == '__main__':
    check_na_cve()
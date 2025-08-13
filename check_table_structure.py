import sqlite3
import sys

try:
    print("Подключение к базе данных...")
    sys.stdout.flush()
    
    conn = sqlite3.connect('cve_data.db')
    c = conn.cursor()
    
    print("Проверяем структуру таблицы...")
    sys.stdout.flush()
    
    # Проверяем структуру таблицы
    c.execute('PRAGMA table_info(vulnerabilities)')
    columns = c.fetchall()
    print("Структура таблицы vulnerabilities:")
    for col in columns:
        print(f"  {col[1]} ({col[2]})")
    sys.stdout.flush()
    
    # Проверяем количество записей
    c.execute('SELECT COUNT(*) FROM vulnerabilities')
    count = c.fetchone()[0]
    print(f"\nКоличество записей: {count}")
    sys.stdout.flush()
    
    # Проверяем первые несколько записей
    c.execute('SELECT * FROM vulnerabilities LIMIT 3')
    rows = c.fetchall()
    print("\nПервые 3 записи:")
    for row in rows:
        print(f"  {row}")
    sys.stdout.flush()
    
    conn.close()
    print("\nГотово!")
    sys.stdout.flush()
    
except Exception as e:
    print(f"Ошибка: {e}")
    sys.stdout.flush()
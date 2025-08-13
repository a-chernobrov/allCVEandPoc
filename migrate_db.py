#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Скрипт для миграции базы данных - добавление поля created_at
"""

import sqlite3
from datetime import datetime

def migrate_database():
    """
    Добавляет поле created_at к существующей таблице vulnerabilities
    """
    conn = sqlite3.connect('cve_data.db')
    c = conn.cursor()
    
    try:
        # Проверяем, существует ли уже поле created_at
        c.execute("PRAGMA table_info(vulnerabilities)")
        columns = [column[1] for column in c.fetchall()]
        
        if 'created_at' not in columns:
            print("Добавляем поле created_at к таблице vulnerabilities...")
            
            # Добавляем новое поле
            c.execute("ALTER TABLE vulnerabilities ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
            
            # Обновляем существующие записи с текущим временем
            c.execute("UPDATE vulnerabilities SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
            
            conn.commit()
            print("Миграция успешно завершена!")
        else:
            print("Поле created_at уже существует в таблице.")
            
    except sqlite3.Error as e:
        print(f"Ошибка при миграции базы данных: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == '__main__':
    migrate_database()
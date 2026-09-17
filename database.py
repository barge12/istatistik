import sqlite3
import os
import re
from werkzeug.security import generate_password_hash

DB_NAME = "database.db"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def tr_slug(text):
    """ Turkish character replacement and slug creation for code generation """
    tr_map = {
        'ç': 'c', 'Ç': 'C', 'ğ': 'g', 'Ğ': 'G', 'ı': 'I', 'İ': 'I', 'i': 'I',
        'ö': 'o', 'Ö': 'O', 'ş': 's', 'Ş': 'S', 'ü': 'u', 'Ü': 'U'
    }
    for k, v in tr_map.items():
        text = text.replace(k, v)
    
    words = re.findall(r'\w+', text)
    if not words:
        return "BRM"
    
    if len(words) == 1:
        code = words[0][:4].upper()
    else:
        code = "-".join([w[:3].upper() for w in words[:3]])
    return code
def generate_auto_code(name, is_sub=False, unit_id=None, table='units'):
    base_code = tr_slug(name)
    conn = get_db_connection()
    cursor = conn.cursor()

    code = base_code
    counter = 1

    while True:
        if table == 'institutes':
            cursor.execute("SELECT id FROM institutes WHERE code = ?", (code,))
        elif is_sub:
            cursor.execute("SELECT id FROM sub_units WHERE code = ?", (code,))
        else:
            cursor.execute("SELECT id FROM units WHERE code = ?", (code,))

        if not cursor.fetchone():
            break
        code = f"{base_code}-{counter}"
        counter += 1

    conn.close()
    return code

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    # Create institutes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS institutes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            is_active BOOLEAN DEFAULT 1
        )
    ''')

    # Migration: units tablosuna institute_id kolonu
    cursor.execute("PRAGMA table_info(units)")
    unit_cols = [col[1] for col in cursor.fetchall()]
    if 'institute_id' not in unit_cols:
        cursor.execute("ALTER TABLE units ADD COLUMN institute_id INTEGER REFERENCES institutes(id)")

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT NOT NULL, -- rootadmin, admin, user
            unit_id INTEGER,
            sub_unit_id INTEGER,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (unit_id) REFERENCES units (id),
            FOREIGN KEY (sub_unit_id) REFERENCES sub_units (id)
        )
    ''')

    # Create data_entries table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS data_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            unit_id INTEGER NOT NULL,
            sub_unit_id INTEGER,
            day INTEGER NOT NULL,
            month INTEGER NOT NULL,
            year INTEGER NOT NULL,
            time TEXT NOT NULL,
            title TEXT NOT NULL,
            note TEXT,
            file_path TEXT,
            special_auth BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (unit_id) REFERENCES units (id),
            FOREIGN KEY (sub_unit_id) REFERENCES sub_units (id)
        )
    ''')

    # Migration checks
    cursor.execute("PRAGMA table_info(units)")
    unit_cols = [col[1] for col in cursor.fetchall()]
    if 'is_active' not in unit_cols:
        cursor.execute("ALTER TABLE units ADD COLUMN is_active BOOLEAN DEFAULT 1")

    cursor.execute("PRAGMA table_info(sub_units)")
    sub_unit_cols = [col[1] for col in cursor.fetchall()]
    if 'is_active' not in sub_unit_cols:
        cursor.execute("ALTER TABLE sub_units ADD COLUMN is_active BOOLEAN DEFAULT 1")

    cursor.execute("PRAGMA table_info(users)")
    user_cols = [col[1] for col in cursor.fetchall()]
    if 'sub_unit_id' not in user_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN sub_unit_id INTEGER REFERENCES sub_units(id)")

    cursor.execute("PRAGMA table_info(data_entries)")
    data_cols = [col[1] for col in cursor.fetchall()]
    if 'sub_unit_id' not in data_cols:
        cursor.execute("ALTER TABLE data_entries ADD COLUMN sub_unit_id INTEGER REFERENCES sub_units(id)")

    # Insert default rootadmin if not exists
    cursor.execute("SELECT * FROM users WHERE username = ?", ("rootadmin",))
    rootadmin = cursor.fetchone()

    if not rootadmin:
        hashed_pw = generate_password_hash("root123")
        cursor.execute('''
            INSERT INTO users (username, password, email, role, is_active)
            VALUES (?, ?, ?, ?, ?)
        ''', ("rootadmin", hashed_pw, "root@admin.com", "rootadmin", True))

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database re-initialized and migrated for units is_active column.")

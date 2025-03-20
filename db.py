import sqlite3

conn = sqlite3.connect('automated.sqlite')
cursor = conn.cursor()

sql_query="""CREATE TABLE users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            fname TEXT,
            lname TEXT,
            education TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
)"""

cursor.execute(sql_query)
import sqlite3

connection = sqlite3.connect('data.db')
cursor = connection.cursor()

create_table = "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username text, password text, salt text)"
cursor.execute(create_table)

create_table = "CREATE TABLE IF NOT EXISTS messages (sender text, receiver text, ciphertext text, time_stamp datetime, read int)"
cursor.execute(create_table)

connection.commit()

connection.close()

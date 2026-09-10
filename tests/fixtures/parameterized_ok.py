import sqlite3


def get_user(conn: sqlite3.Connection, user_id: int):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def get_user_by_name(conn, name: str):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
    return cursor.fetchone()


def get_user_dict(conn, user_id: int):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})
    return cursor.fetchone()

from sqlalchemy import text


def get_user(conn, user_id):
    stmt = text(f"SELECT * FROM users WHERE id = {user_id}")
    return conn.execute(stmt).fetchone()

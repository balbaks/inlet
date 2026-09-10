def build_query(user_id):
    return f"SELECT * FROM users WHERE id = {user_id}"


def run_query(conn, user_id):
    query = build_query(user_id)
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()

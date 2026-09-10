def get_user(conn, user_id):
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = %s" % (user_id,)
    cursor.execute(query)
    return cursor.fetchone()

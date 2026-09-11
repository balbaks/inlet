"""A builder-style receiver with no cursor/connection/session naming
convention, but the argument itself IS a string-shaped SQL expression.
This must still be caught as concatenated: evidence from the argument
shape is sufficient on its own, independent of the receiver's name.
Cursor-like naming is only needed as a fallback when the argument itself
gives no shape evidence (see builder_execute_not_sql.py)."""


class QueryRunner:
    def run(self, table_name):
        return self.execute(f"SELECT * FROM {table_name}")

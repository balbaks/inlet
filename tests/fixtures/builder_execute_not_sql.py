"""Models the real peewee false positive documented in EVALUATION.md: a
query-builder object exposes its own .execute(database) method, where the
argument is a Database/connection object, not SQL text, and the receiver
name gives no cursor/connection evidence either. inlet must not treat
either call below as a DB-idiom candidate at all - not even as uncertain,
since neither the argument shape nor the receiver name gives any evidence
this is a database call in the first place."""


class Query:
    def execute(self, database):
        return database.execute(self)


def save(query, database):
    return query.execute(database)

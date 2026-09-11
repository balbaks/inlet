"""Models the real peewee pattern documented in EVALUATION.md: a
query-builder object exposes its own .execute(database) method, where the
argument is a Database/connection object, not SQL text, and the receiver
name gives no cursor/connection evidence either. As of v0.1.2, this must
come back `uncertain` for both calls below - not excluded. There is no
reliable local-syntax signal that this pair of calls is peewee's
unrelated Query.execute(database) rather than some other package's real
`self.execute(x)` DB wrapper; silently dropping the finding traded a
recoverable false positive for an unrecoverable false negative, which is
worse. See EVALUATION.md's "v0.1.1 -> v0.1.2, a reverted attempt" section."""


class Query:
    def execute(self, database):
        return database.execute(self)


def save(query, database):
    return query.execute(database)

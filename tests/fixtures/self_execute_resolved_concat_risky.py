"""Models Django's SchemaEditor.execute(sql, params) pattern (see
EVALUATION.md): the receiver is `self` - no cursor/connection/session
naming at all - and the query argument is a bare Name at the call site,
but it resolves, via a straight-line assignment in the same function, to
a %-formatted string. This must still come back concatenated: receiver-name
evidence is only consulted once classify_expr has already failed to
resolve the argument to a string shape, never before."""


class SchemaEditor:
    def build_table(self, table, column):
        sql = "CREATE TABLE %s (%s)" % (table, column)
        self.execute(sql)

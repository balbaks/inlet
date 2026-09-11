"""Models Django's real SchemaEditor.execute(sql) pattern (see
EVALUATION.md): `self` is a genuine DB wrapper, `sql` is built by another
method entirely so it isn't locally resolvable, and the receiver name
("self") gives no cursor/connection/session evidence. This is the exact
shape v0.1.1 silently excluded from output - 53 real findings just like
this one, across Django alone. v0.1.2 restores it to `uncertain`: there is
no way to tell, from local syntax, whether `self` here is a real DB
wrapper (as it is) or an unrelated object (as in
builder_execute_not_sql.py's Query.execute(database)) - both must be
surfaced as uncertain, not guessed at in either direction."""


class SchemaEditor:
    def add_field(self, model, field):
        sql = self._create_field_sql(model, field)
        self.execute(sql)

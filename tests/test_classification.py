from pathlib import Path

from inlet.core import scan

FIXTURES = Path(__file__).parent / "fixtures"


def _verdicts(filename: str) -> list[str]:
    findings = scan(FIXTURES / filename)
    assert findings, f"expected at least one finding in {filename}"
    return [f.verdict for f in findings]


def test_parameterized_ok():
    verdicts = _verdicts("parameterized_ok.py")
    assert verdicts == ["parameterized"] * len(verdicts)


def test_fstring_risky():
    assert _verdicts("fstring_risky.py") == ["concatenated"]


def test_percent_format_risky():
    assert _verdicts("percent_format_risky.py") == ["concatenated"]


def test_concat_plus_risky():
    assert _verdicts("concat_plus_risky.py") == ["concatenated"]


def test_django_raw_risky():
    verdicts = _verdicts("django_raw_risky.py")
    assert verdicts == ["concatenated"] * len(verdicts)


def test_sqlalchemy_text_risky():
    verdicts = _verdicts("sqlalchemy_text_risky.py")
    assert verdicts == ["concatenated"] * len(verdicts)


def test_builder_function_uncertain():
    """The wall: a query built in one function and passed into another
    cannot be resolved by single-function-scope AST analysis. It must
    come back uncertain, never a confident (and wrong) guess."""
    assert _verdicts("builder_function_uncertain.py") == ["uncertain"]


def test_str_format_is_concatenated():
    import ast

    from inlet.classify import classify_expr

    tree = ast.parse('"SELECT * FROM users WHERE id = {}".format(user_id)')
    expr = tree.body[0].value
    assert classify_expr(expr, tree, 999) == "concatenated"


def test_unresolvable_function_param_is_uncertain():
    import ast

    from inlet.classify import classify_expr

    tree = ast.parse(
        "def f(query):\n"
        "    cursor.execute(query)\n"
    )
    func = tree.body[0]
    call = func.body[0].value
    name_expr = call.args[0]
    assert classify_expr(name_expr, func, call.lineno) == "uncertain"


def test_builder_execute_not_sql_is_excluded():
    """The peewee false positive from EVALUATION.md: Query.execute(database)
    and database.execute(query) both take a connection/database object, not
    SQL text, and neither receiver is cursor/connection-like. Must produce
    no findings at all - not even uncertain, since there's no evidence
    either call is a database call in the first place."""
    assert scan(FIXTURES / "builder_execute_not_sql.py") == []


def test_builder_execute_with_string_arg_still_caught():
    """A non-cursor-named receiver must not suppress detection when the
    argument itself is unambiguously SQL-shaped - the positive-evidence
    gate is an *or*, not a requirement for cursor-like naming specifically."""
    assert _verdicts("builder_execute_string_arg_risky.py") == ["concatenated"]


def test_self_execute_with_resolved_concat_arg_still_caught():
    """The regression this patch must not reintroduce (found while
    re-scanning Django for EVALUATION.md's post-fix delta): self.execute(sql)
    where sql resolves, via a straight-line assignment in the same
    function, to a %-formatted string. The receiver ("self") gives no
    cursor-like evidence, but the gate must only apply when classify_expr
    still comes back uncertain *after* resolution - not before."""
    assert _verdicts("self_execute_resolved_concat_risky.py") == ["concatenated"]


def test_cursor_call_chain_is_recognized_even_with_unresolvable_arg():
    import ast

    from inlet.detectors import find_candidates

    tree = ast.parse(
        "def f(conn, query):\n"
        "    conn.cursor().execute(query)\n"
    )
    candidates = find_candidates(tree)
    assert len(candidates) == 1
    assert candidates[0].idiom == "generic_execute"
    assert candidates[0].receiver_is_cursor_like is True


def test_execute_with_no_receiver_evidence_is_flagged_accordingly():
    """Detection itself still finds the call site (that's still just a
    name match) - the receiver_is_cursor_like flag is what tells core.scan()
    whether an eventual 'uncertain' verdict is worth keeping. See
    test_builder_execute_not_sql_is_excluded for the end-to-end behavior."""
    import ast

    from inlet.detectors import find_candidates

    tree = ast.parse(
        "def f(query_obj, database):\n"
        "    query_obj.execute(database)\n"
    )
    candidates = find_candidates(tree)
    assert len(candidates) == 1
    assert candidates[0].receiver_is_cursor_like is False


def test_execute_on_conventionally_named_receiver_is_still_a_candidate():
    """Receiver-name evidence must still work for the common, real shape
    (cursor.execute(sql_variable)) where the argument itself isn't
    string-shaped at the call site - this is most of the existing
    fixtures' actual pattern, and it must not regress."""
    import ast

    from inlet.detectors import find_candidates

    for receiver in ("cursor", "conn", "self.connection", "self._conn", "session"):
        tree = ast.parse(f"def f(sql):\n    {receiver}.execute(sql)\n")
        candidates = find_candidates(tree)
        assert len(candidates) == 1, f"expected a candidate for {receiver}.execute(sql)"
        assert candidates[0].idiom == "generic_execute"
        assert candidates[0].receiver_is_cursor_like is True

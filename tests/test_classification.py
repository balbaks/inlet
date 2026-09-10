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

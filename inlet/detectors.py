"""AST visitors that locate candidate DB-execution call sites.

Detection only: these visitors identify *which* calls look like SQL
execution across the four idiom families. They do not judge risk -
that's classify.py's job.
"""

import ast
from dataclasses import dataclass


@dataclass
class Candidate:
    call: ast.Call
    scope: ast.AST          # enclosing FunctionDef/AsyncFunctionDef or Module
    idiom: str               # "raw_db_api" | "django_raw" | "django_extra" | "sqlalchemy_text" | "generic_execute"
    query_expr: ast.AST
    params_present: bool
    # Positive evidence that the receiver of `.execute`/`.raw`/`.extra` is
    # actually a DB-API cursor, connection, or ORM session - see
    # _receiver_is_cursor_like. Always True for sqlalchemy_text, since a
    # bare `text(...)` call has no receiver to judge and no known
    # same-named-but-unrelated API to collide with.
    receiver_is_cursor_like: bool


def _kw(call: ast.Call, name: str):
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_none(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _has_params_arg(call: ast.Call, extra_kw_names: tuple[str, ...] = ("params", "args", "vars")) -> bool:
    if len(call.args) > 1 and not _is_none(call.args[1]):
        return True
    for name in extra_kw_names:
        val = _kw(call, name)
        if val is not None and not _is_none(val):
            return True
    return False


# `execute`/`raw`/`extra` are common enough verbs that unrelated APIs reuse
# them - peewee's Query.execute(database) takes a connection, not SQL text;
# Django's BaseCommand.execute() is CLI dispatch, not a DB call. A bare
# name match isn't evidence of a DB call by itself. This is corroborating
# evidence, checked at candidate-collection time and consulted later by
# core.py once classify_expr has had a chance to resolve the argument -
# see the module docstring in core.py for why the check isn't applied here
# directly.
_CURSOR_LIKE_SEGMENTS = {"cursor", "cur", "curs", "conn", "con", "connection", "session"}


def _receiver_is_cursor_like(value: ast.AST) -> bool:
    """Positive evidence that the object `.execute`/`.raw`/`.extra` is
    being called on is a DB-API cursor, connection, or ORM session - not
    just anything that happens to expose a same-named method.

    Two kinds of evidence, both intentionally narrow and grounded in
    established naming, not any one package's convention: an explicit
    `.cursor()` call immediately in the chain (PEP 249's own term for the
    object), or a receiver whose terminal name segment is one of a small
    set of conventional cursor/connection/session names. Generic names
    like "database"/"db"/"self" are deliberately excluded - see
    EVALUATION.md's peewee finding for why "database" specifically must
    not be on this list.
    """
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute) and value.func.attr == "cursor":
        return True

    if isinstance(value, ast.Name):
        ident = value.id
    elif isinstance(value, ast.Attribute):
        ident = value.attr
    else:
        return False

    segments = [s for s in ident.lower().split("_") if s]
    return bool(segments) and segments[-1] in _CURSOR_LIKE_SEGMENTS


def _classify_call(call: ast.Call) -> tuple[str, ast.AST, bool, bool] | None:
    """Return (idiom, query_expr, params_present, receiver_is_cursor_like)
    if call matches a known idiom family, else None."""
    func = call.func

    if isinstance(func, ast.Attribute) and func.attr == "execute":
        if not call.args:
            return None
        return (
            "generic_execute",
            call.args[0],
            _has_params_arg(call),
            _receiver_is_cursor_like(func.value),
        )

    if isinstance(func, ast.Attribute) and func.attr == "raw":
        if not call.args:
            return None
        return (
            "django_raw",
            call.args[0],
            _has_params_arg(call),
            _receiver_is_cursor_like(func.value),
        )

    if isinstance(func, ast.Attribute) and func.attr == "extra":
        where = _kw(call, "where")
        if where is None:
            return None
        query_expr = where
        if isinstance(where, ast.List) and where.elts:
            query_expr = where.elts[0]
        params_present = _kw(call, "params") is not None
        return (
            "django_extra",
            query_expr,
            params_present,
            _receiver_is_cursor_like(func.value),
        )

    is_text_name = isinstance(func, ast.Name) and func.id == "text"
    is_text_attr = isinstance(func, ast.Attribute) and func.attr == "text"
    if is_text_name or is_text_attr:
        if not call.args:
            return None
        return ("sqlalchemy_text", call.args[0], False, True)

    return None


class QueryCallVisitor(ast.NodeVisitor):
    """Walks a module's AST, tracking enclosing function scope, and
    collects every call site that matches a recognized DB-execution idiom.
    """

    def __init__(self) -> None:
        self.candidates: list[Candidate] = []
        self._scope_stack: list[ast.AST] = []

    def _current_scope(self) -> ast.AST:
        return self._scope_stack[-1]

    def visit_Module(self, node: ast.Module) -> None:
        self._scope_stack.append(node)
        self.generic_visit(node)
        self._scope_stack.pop()

    def _visit_function(self, node) -> None:
        self._scope_stack.append(node)
        self.generic_visit(node)
        self._scope_stack.pop()

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_Call(self, node: ast.Call) -> None:
        matched = _classify_call(node)
        if matched is not None:
            idiom, query_expr, params_present, receiver_is_cursor_like = matched
            self.candidates.append(
                Candidate(
                    call=node,
                    scope=self._current_scope(),
                    idiom=idiom,
                    query_expr=query_expr,
                    params_present=params_present,
                    receiver_is_cursor_like=receiver_is_cursor_like,
                )
            )
        self.generic_visit(node)


def find_candidates(tree: ast.Module) -> list[Candidate]:
    visitor = QueryCallVisitor()
    visitor.visit(tree)
    return visitor.candidates

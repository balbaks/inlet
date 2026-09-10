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


def _classify_call(call: ast.Call) -> tuple[str, ast.AST, bool] | None:
    """Return (idiom, query_expr, params_present) if call matches a known
    idiom family, else None."""
    func = call.func

    if isinstance(func, ast.Attribute) and func.attr == "execute":
        if not call.args:
            return None
        return ("generic_execute", call.args[0], _has_params_arg(call))

    if isinstance(func, ast.Attribute) and func.attr == "raw":
        if not call.args:
            return None
        return ("django_raw", call.args[0], _has_params_arg(call))

    if isinstance(func, ast.Attribute) and func.attr == "extra":
        where = _kw(call, "where")
        if where is None:
            return None
        query_expr = where
        if isinstance(where, ast.List) and where.elts:
            query_expr = where.elts[0]
        params_present = _kw(call, "params") is not None
        return ("django_extra", query_expr, params_present)

    is_text_name = isinstance(func, ast.Name) and func.id == "text"
    is_text_attr = isinstance(func, ast.Attribute) and func.attr == "text"
    if is_text_name or is_text_attr:
        if not call.args:
            return None
        return ("sqlalchemy_text", call.args[0], False)

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
            idiom, query_expr, params_present = matched
            self.candidates.append(
                Candidate(
                    call=node,
                    scope=self._current_scope(),
                    idiom=idiom,
                    query_expr=query_expr,
                    params_present=params_present,
                )
            )
        self.generic_visit(node)


def find_candidates(tree: ast.Module) -> list[Candidate]:
    visitor = QueryCallVisitor()
    visitor.visit(tree)
    return visitor.candidates

"""Turns a candidate call site's query expression into a verdict.

Pure and independently testable: everything here takes an AST expression
(plus the enclosing scope, for local Name resolution) and returns one of
"parameterized", "concatenated", or "uncertain". No file I/O.
"""

import ast

PARAMETERIZED = "parameterized"
CONCATENATED = "concatenated"
UNCERTAIN = "uncertain"


def _resolve_name(name: str, scope: ast.AST, before_lineno: int) -> ast.AST | None:
    """Find the value last assigned to `name` in this scope's direct body
    before `before_lineno`. Only sees straight-line assignments in the same
    function (or module) scope - the documented single-function-scope
    limit, not a bug.
    """
    best = None
    for stmt in getattr(scope, "body", []):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(stmt, ast.Assign) and stmt.lineno < before_lineno:
            for target in stmt.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    if best is None or stmt.lineno > best.lineno:
                        best = stmt
    return best.value if best else None


def classify_expr(expr: ast.AST, scope: ast.AST, reference_lineno: int) -> str:
    """Classify a query-argument expression as parameterized, concatenated,
    or uncertain."""

    # A bare literal string can never carry untrusted data by construction -
    # whatever placeholder syntax it contains is inert text.
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return PARAMETERIZED

    if isinstance(expr, ast.JoinedStr):
        has_interpolation = any(isinstance(v, ast.FormattedValue) for v in expr.values)
        return CONCATENATED if has_interpolation else PARAMETERIZED

    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
        return CONCATENATED

    if isinstance(expr, ast.Call):
        func = expr.func
        if isinstance(func, ast.Attribute) and func.attr == "format":
            return CONCATENATED
        if (isinstance(func, ast.Name) and func.id == "text") or (
            isinstance(func, ast.Attribute) and func.attr == "text"
        ):
            if not expr.args:
                return UNCERTAIN
            return classify_expr(expr.args[0], scope, reference_lineno)
        # Any other call (e.g. a helper function building the query
        # elsewhere) requires interprocedural dataflow analysis to
        # resolve. That's out of scope for v0.1.0 - say so honestly.
        return UNCERTAIN

    if isinstance(expr, ast.Name):
        resolved = _resolve_name(expr.id, scope, reference_lineno)
        if resolved is None:
            return UNCERTAIN
        return classify_expr(resolved, scope, reference_lineno)

    return UNCERTAIN

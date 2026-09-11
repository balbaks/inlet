import ast
from pathlib import Path

from .classify import classify_expr
from .detectors import find_candidates
from .result import Finding


def _scan_file(path: Path) -> list[Finding]:
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return []

    findings: list[Finding] = []
    for candidate in find_candidates(tree):
        verdict = classify_expr(candidate.query_expr, candidate.scope, candidate.call.lineno)
        # A candidate that resolves to "uncertain" with no corroborating
        # evidence that the receiver is a cursor/connection/session (see
        # detectors._receiver_is_cursor_like) was never shown to be a
        # database call in the first place - e.g. peewee's
        # Query.execute(database), where the argument is a connection
        # object, not SQL. Drop it rather than report a guess about
        # something that was never plausibly a query. This check runs
        # after classification, not at detection time, specifically so it
        # doesn't short-circuit the common `x = "..." % ...; cursor.x(y)`
        # pattern where the argument only turns out to be string-shaped
        # once classify_expr resolves the Name - see EVALUATION.md's
        # "Post-fix delta" section.
        if verdict == "uncertain" and not candidate.receiver_is_cursor_like:
            continue
        snippet = ast.get_source_segment(source, candidate.call) or ast.unparse(candidate.call)
        findings.append(
            Finding(
                file=str(path),
                line=candidate.call.lineno,
                call=ast.unparse(candidate.call.func),
                verdict=verdict,
                snippet=snippet,
            )
        )
    return findings


def scan(path: str | Path) -> list[Finding]:
    """Scan a Python file or directory for DB-execution call sites."""
    root = Path(path)
    findings: list[Finding] = []

    if root.is_file():
        findings.extend(_scan_file(root))
    else:
        for py_file in sorted(root.rglob("*.py")):
            findings.extend(_scan_file(py_file))

    return findings

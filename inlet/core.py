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

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
        # v0.1.1 dropped a candidate entirely here when it resolved to
        # "uncertain" and the receiver gave no corroborating cursor/
        # connection/session evidence (detectors._receiver_is_cursor_like) -
        # meant to filter peewee's Query.execute(database), where the
        # argument is a connection object, not SQL. It also silently
        # dropped 94 real DB call sites elsewhere (Django's
        # SchemaEditor.execute(), SQLAlchemy's own Engine/Session
        # internals, and more) whose receiver just happened to be named
        # something generic like `self` - there is no local-syntax signal
        # that distinguishes those from peewee's false positive. Reverted
        # in v0.1.2: a finding that's merely uncertain is something a human
        # can dismiss; a finding that was never reported cannot be. See
        # EVALUATION.md's "v0.1.1 -> v0.1.2, a reverted attempt" section.
        # `receiver_is_cursor_like` is still computed and still attached to
        # the candidate (see detectors.py) - it's just never used to remove
        # a finding. A confident parameterized/concatenated verdict has
        # always come from classify_expr resolving the argument itself
        # (unchanged since v0.1.0, and independent of the receiver);
        # nothing here downgrades or upgrades that. The receiver signal is
        # kept as an upgrade-only lever for future use, not a removal
        # lever - see EVALUATION.md.
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

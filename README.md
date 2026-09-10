# inlet

`inlet` maps every place a Python codebase touches a database and
classifies each call site by risk *shape*: `parameterized`,
`concatenated`, or `uncertain`.

## What this is not

`inlet` is a static scanner, not an exploitability scanner. It never
executes any code. It does not prove that a `concatenated` or `uncertain`
finding is a real, exploitable vulnerability — it only tells you the shape
of the call site so you know where to look. Treat every `concatenated` or
`uncertain` hit as a lead, not a verdict: pair it with actual verification
(manual review, or an execution-based tool) before treating it as a real
bug.

## The scope wall

`inlet` resolves query arguments using only what's visible in **local,
single-function scope** — parsed with `ast`, no cross-file or
cross-function dataflow tracing. If a query string is built in one
function and passed into another as an argument, `inlet` cannot follow it
there. Rather than guess, it reports `uncertain`.

This is a deliberate, documented limit, not an oversight. Resolving that
case correctly requires interprocedural dataflow analysis — project-scale
tooling territory that's out of scope for v0.1.0. See
[`tests/fixtures/builder_function_uncertain.py`](tests/fixtures/builder_function_uncertain.py)
and its test in
[`tests/test_classification.py`](tests/test_classification.py), which
assert this exact case comes back `uncertain` and nothing else.

## Origin

This tool grew out of a gap named directly in a companion project,
secfix's own walls doc: Wall A was "DB-idiom detection —
`connection.cursor()` wasn't recognized, only bare getters." `inlet`
generalizes that fix into its own standalone tool, built to handle more
idioms than secfix ever needed to.

## Verdicts

- **`parameterized`** — the query argument is a literal string (a literal
  can't carry untrusted data, whether or not it contains `%s`/`?`/`:name`
  placeholders and whatever params were passed alongside it). The safe
  shape.
- **`concatenated`** — the query argument is built inline via an f-string,
  string `+` concatenation, `%` formatting, or `.format()` — untrusted
  data could land directly in the SQL text. The risky shape.
- **`uncertain`** — the query argument is a variable whose value can't be
  resolved to a literal within the same function scope. The honest answer
  when confident resolution isn't possible.

## Idiom coverage

- Raw DB API (`sqlite3`/`psycopg2`-style `cursor.execute(...)`)
- Django ORM (`.raw(...)`, `.extra(where=[...])`)
- SQLAlchemy (`text(...)`, `.execute(...)`)
- Generic `<anything>.execute(...)` calls

Python only. No severity scoring, no auto-fix — by design, not by
laziness.

## Usage

### Library

```python
from inlet import scan

for finding in scan("path/to/project"):
    print(finding.file, finding.line, finding.call, finding.verdict)
```

### CLI

```console
$ inlet scan path/to/project
$ inlet scan path/to/project --only concatenated,uncertain
```

Findings print grouped by verdict, risky (`concatenated`) first.

## Proof

Every classification rule is asserted by test, not eyeballed:
[`tests/test_classification.py`](tests/test_classification.py) runs
against seven fixtures covering every idiom family and both the safe and
risky shapes, plus the cross-function wall case.

```console
$ pip install -e .
$ pytest
```

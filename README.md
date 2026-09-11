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

## Walls

`inlet` has two known, deliberate walls — limits it hits by design, not
gaps it just hasn't gotten to yet. Both are named here on purpose, the same
way secfix's own walls doc named its limits instead of overselling scope
(see Origin, below). [`EVALUATION.md`](EVALUATION.md) is the proof for
both, not just the description: it runs `inlet`, unmodified, against real
open-source packages and shows exactly what each wall costs in practice.

### Wall 1: single-function scope

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

### Wall 2: idiom-name coverage

`inlet` recognizes exactly four idiom families, matched by call *name*:
`.execute(...)`, Django's `.raw(...)`/`.extra(...)`, and SQLAlchemy's
`text(...)`. That list does not grow to chase every framework's own
vocabulary for "run this SQL." Real frameworks wrap SQL execution behind
their own abstraction names — Airflow's `hook.get_records()`, Tortoise
ORM's `field.like()`, a plain Jinja-macro helper function like Apache
Superset's `where_in` — and none of those are a call to anything spelled
`execute`/`raw`/`extra`/`text`, so none of them are detected as a candidate
at all. Not `uncertain`. Nothing.

[`EVALUATION.md`](EVALUATION.md) is the proof, not a claim: of 5 real,
independently-verified historical SQL-injection CVEs run against the
unmodified tool, **4 were missed** — 3 for exactly this reason (Apache
Superset's `CVE-2023-49736`, Tortoise ORM's `CVE-2020-11010`, Apache
Airflow's `CVE-2025-30473`), and the 4th (Django's `CVE-2022-28346`) for
the closely related reason that the vulnerable query is assembled via
`", ".join(...)` across several functions and files, never taking one of
the four recognized shapes at the point it's finally executed. See
`EVALUATION.md` §2–3 for the finding-by-finding detail.

This is the same trap secfix's own walls doc named first, one level up:
Wall A there was "DB-idiom detection — `connection.cursor()` wasn't
recognized, only bare getters," and the fix was never "add
`connection.cursor()` to the list" — it was recognizing that there is no
finite list. Every ORM and framework invents its own verb for "execute
this," and chasing each one by name is an unbounded, ever-growing list
that's always one framework behind. **This is not planned to be solved by
adding more names.** Widening idiom coverage from 4 names to 40 would still
miss the 41st framework's execute-shaped method; the exercise would just be
re-losing the same fight secfix's Wall A already identified. If this wall
is ever meaningfully narrowed, it will need a different kind of approach
entirely (e.g. following calls through actual type information rather than
matching on spelling) — not a longer name list, and that is not currently
planned or in progress.

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

`.execute(...)`/`.raw(...)`/`.extra(...)` calls are matched by name alone,
which real code sometimes reuses for something that isn't SQL (peewee's
own `Query.execute(database)` takes a connection object, not a query — see
`EVALUATION.md`). Since v0.1.1, a call that resolves to `uncertain` is only
reported if there's positive evidence the receiver is actually a DB
cursor/connection/session (an explicit `.cursor()` in the chain, or a
conventional name like `cursor`/`conn`/`session`); otherwise it's dropped
rather than reported as a guess. This measurably fixes false positives on
some real code and measurably drops some real (if already low-confidence)
findings on other real code where the same wrapper method is named
something generic like `self` — `EVALUATION.md`'s "Post-fix delta" section
has the exact, unspun numbers both ways.

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
against ten fixtures covering every idiom family, both the safe and risky
shapes, the cross-function wall case, and (since v0.1.1) the
execute-name-collision exclusion and its true-positive-preservation
counterpart.

```console
$ pip install -e .
$ pytest
```

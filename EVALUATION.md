# EVALUATION.md — inlet against a real-world corpus

This is a measurement, not a demo. `inlet`'s fixture tests (`tests/fixtures/*.py`)
prove the classifier does what it's designed to do on code written specifically
to exercise it. This document runs the unmodified tool against 15 real PyPI
packages nobody wrote with `inlet` in mind, and reports what actually happened
— including where it did not go well.

Run once, on 2026-09-11, against the versions listed below. `inlet` version
`0.1.0`, invoked exactly as `inlet scan <path>` with no flags.

## 1. Methodology

### Corpus selection

15 packages, split into two groups:

- **Group A (5 packages)** — a documented, independently verifiable historical
  SQL-injection issue involving raw or string-built queries (not ORM misuse
  unrelated to string building). Selection required, before any scanning: a
  CVE ID or GitHub Security Advisory, a fix commit or advisory description
  specific enough to locate the vulnerable file/function/line, and (where
  possible) an installable/clonable version that still contains the
  pre-fix code.
- **Group B (10 packages)** — popular, actively-maintained packages with no
  known SQL-injection history, chosen to exercise more than one of inlet's
  four idiom families (raw DB-API `cursor.execute`, Django ORM, SQLAlchemy
  `text()`/`.execute()`, generic `.execute()`) and to include both
  application-shaped code (ORMs, query builders) and library-internal code.

**How CVE claims were verified.** Every Group A entry below was checked
against at least one primary/near-primary source — a GitHub Security
Advisory, the project's own security-release notes, or a linked fix commit
— via live web lookup, and then independently re-derived by reading the
actual pre-fix source in the cloned/downloaded package (not just trusting
the advisory's prose). Where an advisory named a file/function but not a
precise post-refactor line number, the line was located by grep/read against
the source at the cited vulnerable version. No CVE or vulnerability claim in
this document is asserted without that source having been fetched and read
in this session. One initially-promising candidate (pgAdmin 4,
CVE-2026-7815) was researched and its vulnerable code located, but was
**dropped** from Group A before scanning — see §4 — rather than counted as a
"miss," because the vulnerable code path never reaches a Python `.execute()`/
`.raw()`/`.extra()`/`text()` call at all (it shells out to `psql`), so
scanning it would not have been a fair test of the tool.

**Hit / miss / partial.** A **hit** means an inlet finding lands on the
specific vulnerable line (or the line containing the vulnerable expression)
with verdict `concatenated`. A **miss** means no finding at any verdict
covers that line — the tool is silent about the vulnerable code entirely. A
**partial** is a case that doesn't fit that binary: the vulnerable line *is*
present in inlet's output, but under a different (downgraded) verdict than
`concatenated`, changing what a user would conclude from it. That distinction
turned out to matter — see §3.

**False-positive review (Group B).** For each Group B package, every
`concatenated` finding was read in full unless the package produced a large
volume (SQLAlchemy, Django), in which case the `concatenated` bucket was
read to a documented point of coverage and the `uncertain` bucket was spot
sampled. All packages' full inlet output (including code snippets) was
available inline, so "review" here means reading the flagged call site and
its enclosing function in the extracted source, not just eyeballing the verdict
name. Coverage per package is stated exactly in §2.

**Honest limits of this evaluation itself:**

- **Single evaluator, not blind.** One reviewer (this session) both selected
  the corpus and judged hit/miss/false-positive, with knowledge of inlet's
  source going in. There was no second reviewer and no pre-registration of
  which packages would be chosen before their CVE history was known.
- **Small N.** 5 Group A packages is enough to see a pattern, not enough to
  produce a defensible hit rate with a confidence interval. Two of the five
  misses share almost the identical root cause (idiom-name coverage), so the
  five data points are not five independent trials.
- **Sampling on the two largest Group B packages.** SQLAlchemy's `uncertain`
  bucket (421 findings) and about half of Django 5.1.3's `concatenated` (76)
  and `uncertain` (81) buckets were spot-sampled, not exhaustively read — see
  §2 for exact coverage. Conclusions about those two packages' false-positive
  rate are qualitative, not a precise percentage.
- **Manual review subjectivity.** "Genuine risk shape" vs. "false positive"
  vs. "ambiguous" is a judgment call, especially for values like `table` or
  `schema_name` that are attacker-reachable in some deployments and pure
  local config in others. Classifications below say what data the interpolated
  value actually comes from at that call site, so a reader can disagree with
  the label while still using the underlying fact.
- **Group A selection bias toward frameworks/ORMs.** CVEs with a public fix
  commit and a precise vulnerable line are disproportionately easy to find in
  large, well-governed projects (Django, Apache-umbrella projects, popular
  ORMs) — and that code disproportionately routes SQL through internal
  abstraction layers (`hook.get_records()`, `Query.execute(db)`,
  `field.like()`) rather than a bare `cursor.execute(f"...")` in application
  code. This is discussed as a finding in its own right in §3, but it also
  means Group A is not a random sample of "SQLi bugs in Python" — it's
  biased toward exactly the code shape most likely to defeat inlet's idiom
  list, because that's where verifiable CVEs were findable in the time
  available.

## 2. Results

All scans run via `inlet scan <path>` with no flags, single-threaded, on a
lightly loaded machine. No timeouts, no memory limits hit.

### Group A — packages with a documented historical SQLi issue

| Package | Version scanned | LOC scanned | concatenated / uncertain / parameterized | Scan time | CVE | Verdict |
|---|---|---|---|---|---|---|
| Django | 3.2.12 (pre-fix) | 130,402 | 74 / 69 / 75 | 2.06s | CVE-2022-28346 | **MISS** |
| Apache Superset | 2.1.2 (pre-fix) | 116,636 | 21 / 102 / 11 | 1.51s | CVE-2023-49736 | **MISS** |
| Tortoise ORM | 0.16.5 (pre-fix) | 9,314 | 2 / 5 / 2 | 0.21s | CVE-2020-11010 | **MISS** |
| Archery (hhyo/Archery) | 1.9.0 (pre-fix) | 23,990 | 6 / 31 / 15 | 0.48s | CVE-2023-30556 | **PARTIAL** |
| apache-airflow-providers-common-sql | 1.24.0 (pre-fix) | 3,081 | 0 / 3 / 0 | 0.11s | CVE-2025-30473 | **MISS** |

**0 clean hits, 1 partial, 4 misses**, out of 5.

Detail on each:

**Django — CVE-2022-28346 (MISS).** `QuerySet.annotate()`/`.aggregate()`/
`.extra()` let a caller pass a dict whose keys become column aliases; before
the fix, Django didn't validate those keys, so a crafted alias like
`` `injected"); --` `` could break out of the generated SQL
(fixed in `django/db/models/sql/query.py` by commit
[`2044dac5c69`](https://github.com/django/django/commit/2044dac5c6968441be6f534c4139bcf48c5c7e48),
adding `FORBIDDEN_ALIAS_PATTERN`/`check_alias()`). The alias never appears
as an f-string, `%`-format, or `.format()` expression argument to a
recognized call — it's assembled by `SQLCompiler.as_sql()` via list
concatenation/`", ".join(...)` across several methods in
`django/db/models/sql/compiler.py`, and the finished SQL text only reaches an
`.execute()` call many frames later, in
`django/db/backends/utils.py:82/84` (`self.cursor.execute(sql)` /
`self.cursor.execute(sql, params)`). inlet does flag those two lines —
but as `uncertain`, generically, the same way it flags every one of the
hundreds of other `cursor.execute(sql, params)` calls in Django's backend
layer. There is nothing in inlet's output that points a reader anywhere near
`query.py`'s alias handling; the "hit" would be indistinguishable from noise.
Root cause: idiom coverage (`.format()`/`+`/`%` aren't used at the vulnerable
site) combined with the documented cross-function scope wall.

**Apache Superset — CVE-2023-49736 (MISS).** The `where_in` Jinja macro in
`superset/jinja_context.py`, exposed to user-authored SQL Lab query
templates, quoted values by hand (`value.replace(mark, mark * 2)`) instead of
using SQLAlchemy bind parameters — a caller-supplied `mark` character could
defeat the escaping (fixed by replacing it with a `WhereInMacro` class using
`bindparam()`; commit
[`1d403dab982`](https://github.com/apache/superset/commit/1d403dab9822a8cee6108669c53e53fad881c75)).
`inlet scan` produces **zero** findings anywhere in `jinja_context.py` — not
`uncertain`, not anything. `where_in` is a plain function that builds and
returns a string; it never calls anything named `execute`, `raw`, `extra`,
or `text`, so it never becomes a detection candidate in the first place. Root
cause: idiom coverage — the vulnerable code isn't a call site inlet looks at
at all.

**Tortoise ORM — CVE-2020-11010 (MISS).** `contains`/`starts_with`/
`ends_with` filters in `tortoise/filters.py` built `field.like(f"%{value}%")`
without escaping SQL `LIKE` wildcard/escape characters in `value`, letting a
crafted filter value change match semantics or, per the advisory, enable SQL
injection on MySQL (fixed by adding `escape_like()` and a custom `Like`
criterion with an explicit `ESCAPE` clause; commit
[`91c364053e0`](https://github.com/tortoise/tortoise-orm/commit/91c364053e0ddf77edc5442914c6f049512678b3)).
Same shape as Superset: `field.like(...)` builds a pypika `Criterion` object,
not an argument to `.execute()`/`.raw()`/`.extra()`/`text()`. `inlet scan`
has no findings in `filters.py` at all. The eventual `.execute()` calls in
`tortoise/backends/*/client.py` take a `query` object built by pypika's
compiler several layers away — outside single-function scope even if the
idiom had matched. Root cause: idiom coverage.

**hhyo/Archery — CVE-2023-30556 / GHSA-6pv9-9gq7-hr68 (PARTIAL).** The
advisory's cited `sql/sql_optimize.py:optimize_sqltuningadvisor` forwards a
user-controlled `db_name` into
`sql/engines/oracle.py:sqltuningadvisor()`, which builds:

```python
create_task_sql = f"""DECLARE
    ...
    user_name   => '{db_name}',
    ...
    END;"""
...
cursor.execute(create_task_sql)          # oracle.py:1347
```

This is exactly the shape `inlet` exists to catch: an f-string assigned to a
variable, then passed to `cursor.execute()`. `inlet scan` *does* list line
1347 (and the adjacent `get_task_sql` at 1352) — but under **`uncertain`**,
not `concatenated`. The reason is a gap in `classify.py`'s `_resolve_name`,
which only scans a scope's *direct* `body` list for the assignment
(`for stmt in getattr(scope, "body", [])`). Here the f-string assignment sits
inside a `try:` block, one level of nesting below the function's direct body,
so `_resolve_name` never finds it, the `Name` fails to resolve, and
`classify_expr` falls through to `uncertain`. This is a **same-function**
case — no cross-function or cross-file dataflow is required, which is the
limit the README documents — so it's a distinct, previously-undocumented gap:
any assignment inside `try`/`if`/`for`/`while`/`with` is invisible to name
resolution even when it's in the same function as the `.execute()` call.
Confirmed independently: Archery's other f-string→`execute()` sites that sit
in *straight-line* function bodies (no enclosing block) — e.g.
`sql/engines/oracle.py:574`, `sql/engines/mssql.py:310` — are correctly
classified `concatenated`. Practically: a user following the README's
own recommended workflow (`--only concatenated,uncertain`) would still see
line 1347 in their output, so this isn't a silent miss — but it's filed
under the "honest ambiguity" bucket the README explicitly distinguishes from
"the risky shape," which downgrades how a time-pressured reviewer would
triage it.

**Airflow common-sql provider — CVE-2025-30473 (MISS).**
`SQLTableCheckOperator`/`SQLColumnCheckOperator` in
`airflow/providers/common/sql/operators/sql.py` accepted an unsanitized
`partition_clause` and spliced it into a WHERE clause
(`f"WHERE {self.partition_clause}"`, then `.format()`-ed into a larger SQL
template), letting an authenticated UI user inject SQL when triggering a DAG
(fixed by rejecting `;` in `_initialize_partition_clause()`; PR
[apache/airflow#48098](https://github.com/apache/airflow/pull/48098)). The
finished query is run via `hook.get_records(self.sql)` inside the
operator's own `execute(self, context)` method — Airflow's DB-hook
abstraction (`get_records`, `run`, `get_first`) never calls a method literally
named `execute`, `raw`, `extra`, or `text` on the query text itself (the
method named `execute` here is the Airflow *operator* lifecycle method, not a
DB call). `inlet scan` on this package produces exactly 3 findings, all in
`hooks/sql.py`, none of them anywhere near `operators/sql.py`. Root cause:
idiom coverage.

### Group B — popular packages, no known SQLi history

| Package | Version | LOC scanned | concatenated / uncertain / parameterized | Scan time | Review coverage |
|---|---|---|---|---|---|
| SQLAlchemy | 2.0.52 | 239,903 | 26 / 421 / 70 | 2.49s | concatenated: all 26; uncertain: ~10 spot-sampled |
| peewee | 4.5.1 | 22,337 | 8 / 33 / 16 | 0.55s | all 41 read |
| records | 0.6.0 | 907 | 0 / 6 / 0 | 0.07s | all 6 read |
| dataset | 2.0.0 | 1,727 | 0 / 11 / 0 | 0.09s | all 11 read |
| SQLModel | 0.0.42 | 20,646 | 0 / 3 / 6 | 0.29s | all 3 read |
| aiosqlite | 0.22.1 | 1,483 | 3 / 2 / 68 | 0.11s | all 5 read |
| djangorestframework | 3.18.1 | 15,461 | 0 / 0 / 0 | 0.36s | n/a — zero candidates |
| Flask-SQLAlchemy | 3.1.1 | 2,204 | 0 / 4 / 0 | 0.08s | all 4 read |
| Alembic | 1.19.2 | 28,931 | 0 / 11 / 0 | 0.31s | all 11 read |
| Django (patched) | 5.1.3 | 155,102 | 76 / 81 / 67 | 1.86s | concatenated: ~40/76; uncertain: ~44/81 |

Total: **~772,000 LOC, 15 scans, ~10.6s combined scan time, 0 crashes, 0
unhandled exceptions.** Two packages (Apache Superset, Archery) produced
`SyntaxWarning` noise on stderr from Python's own `ast.parse()` tripping over
unescaped backslashes in *their* regex string literals (e.g.
`re.match("\[None\]\.\[.*\]\(id:(\d+)\)", ...)`) — not an inlet defect, but
worth naming as a real-world rough edge: `inlet`'s stdout output was clean
and correct in both cases, but a user piping stderr to a log would see
warnings that have nothing to do with SQL injection.

**False-positive/true-positive breakdown from manual review:**

*`concatenated` bucket (SQLAlchemy full 26 + peewee full 8 + aiosqlite full 3
+ ~40 of Django's 76 = ~77 findings reviewed).* Zero were **shape**
misclassifications — every one is a real f-string/`%`/`.format()`/`+`
expression landing directly in a `.execute()`/`text()` argument, matching
inlet's own definition of `concatenated` exactly. But the large majority
interpolate values that are not attacker-reachable in normal use: DB dialect
config (`isolation level`, `charset_name`, `schema_name`, `passphrase` —
SQLAlchemy/peewee session/connection setup), small fixed-choice ternaries
(`"READ ONLY" if value else "READ WRITE"`), or `quote_name()`-escaped
internal model metadata (`model._meta.db_table`, `field.column` — Django's
schema-migration DDL, ~35 of the ~40 Django hits reviewed). A handful are
plausibly attacker-influenced depending on deployment (Django's cache-table
`table` name comes from `settings.CACHES`, which is operator config, not
request data, in virtually every real deployment — still worth a human
glance, correctly flagged as `concatenated`, but not "urgent"). **Net read:**
inlet's shape classifier itself has a low false-positive rate on this
sample — it isn't flagging non-SQL string building as SQL. What inflates the
bucket in mature libraries is that most real `%`/f-string SQL construction
in code this well-audited is internal plumbing, not raw user-data
concatenation — which is exactly what the README says inlet cannot tell you
("it only tells you the shape... pair with actual verification").

*`uncertain` bucket.* Two clear, quantifiable false-positive patterns:

- **peewee: ~22 of 33 (≈67%) are a naming collision, not query-string
  ambiguity.** peewee's `Query` objects define their own `.execute(database)`
  method — "run this query against this database" — the *inverse* calling
  convention from `cursor.execute(sql)`. `inlet`'s generic-execute idiom
  matches any `.attr == "execute"` call and treats `call.args[0]` as "the
  query expression" unconditionally; for `database.execute(self)`,
  `self.execute(database)`, `clone.execute(database)`, and 19 more instances
  in `peewee.py`/`playhouse/*.py`, that first argument is a `Database` or
  connection object, never a SQL string, so classifying it as
  "uncertain SQL" is not just conservative, it's about the wrong thing
  entirely. The remaining ~11 genuinely are `cursor.execute(sql, params)`
  with an unresolvable `sql`/`statement`/`stmt` — correct, honest
  `uncertain`.
- **Django: at least 5 of ~44 reviewed (≈11%) are `BaseCommand.execute()`
  dispatch, unrelated to SQL.** `django/core/management/commands/
  createsuperuser.py:90`, `django/core/management/__init__.py:194`,
  `django/core/management/base.py:413`, `runserver.py:75`,
  `sqlmigrate.py:39` are all `super().execute(*args, **options)` /
  `command.execute(*args, **defaults)` — Django's management-command
  dispatch convention (analogous to `argparse` handler dispatch), which
  happens to also be named `execute`. Same root cause as peewee: idiom
  matching is name-only, with no check on what kind of object `execute` is
  being called on.
- A related but distinct case, found in SQLAlchemy's `uncertain` sample and
  in `records.py`: `text(query).bindparams(...)` / `.columns(...)` chains.
  `inlet` unwraps exactly one level of a `text(...)` call
  (`classify.py`'s special-case for `func.attr == "text"` recurses into
  `expr.args[0]`), but real SQLAlchemy code almost always chains
  `.bindparams()`/`.columns()` after `text(...)`, e.g.
  `sqlalchemy/dialects/mssql/base.py:3430`:
  `connection.execution_options(...).execute(sql.text(f"""...{filter_definition}...""").bindparams(...).columns(...))`.
  Because the outermost call in the chain is `.columns(...)`, not
  `text(...)`, `classify_expr` never reaches the f-string interpolating
  `filter_definition` and falls back to `uncertain` — even though the
  interpolation is real and sits one property-access away from a case inlet
  handles correctly. This isn't a naming collision like the two above; it's
  a real concatenation-shaped expression that inlet's `text()`-unwrapping is
  too narrow to reach, which argues `uncertain` is *underclassifying* here,
  not being appropriately cautious.
- Everything else reviewed in the `uncertain` bucket (records, dataset,
  SQLModel, Flask-SQLAlchemy, Alembic, and the non-collision remainder of
  peewee/Django/SQLAlchemy) looks like `uncertain` doing exactly its
  documented job: a real DB-execute call whose query text is a function
  parameter, a return value from another call, or otherwise genuinely
  unresolvable without interprocedural analysis. `records.py`, whose entire
  purpose is running caller-supplied raw SQL
  (`self._conn.execute(text(query).bindparams(**params))` where `query` is a
  parameter), is the cleanest example of correct, useful `uncertain`.

**djangorestframework produced zero findings of any verdict.** DRF's
filtering/ordering machinery builds Django ORM `QuerySet`s, not raw SQL, so
none of inlet's four idiom patterns ever match — not a false negative in any
meaningful sense (there's no raw-SQL code to miss), but a useful data point
that inlet correctly stays silent rather than forcing a match on
ORM-only code.

## 3. Honest read

**Where inlet worked.** It did not crash, hang, or emit a wrong exit code
once across ~772K lines of real-world code spanning very different coding
styles (Django's DDL string templates, SQLAlchemy's fluent dialect code,
Archery's Chinese-commented Oracle backup tooling, peewee's compact
single-file module). Scan time is a non-issue (10.6s combined). Where the
vulnerable expression is a literal f-string/`%`/`.format()`/`+` expression
sitting as a direct argument to a recognized call, in a straight-line
function body, it is reliably classified `concatenated` — confirmed on real
(non-fixture) code in SQLAlchemy, peewee, Archery, aiosqlite, and Django's
DDL layer. The false-positive rate on the *shape* question specifically
(is this really a string-built SQL argument?) looks low across everything
manually reviewed — inlet is not, in this sample, flagging arbitrary string
formatting as SQL.

**Where it missed, and why that's not just "the scope wall."** Four of five
Group A CVEs were complete misses, and the fifth was a partial (right line,
wrong verdict). Only one of those five failures is attributable to the
scope wall the README documents (cross-function/cross-file dataflow,
demonstrated in `tests/fixtures/builder_function_uncertain.py`). The other
four have a different, undocumented cause each time real code was checked:

1. **Idiom-name coverage is narrower than real SQL-adjacent code.** Three of
   five Group A misses (Superset, Tortoise ORM, Airflow) never reach a
   recognized call at all — the vulnerable string-building happens in a
   plain helper function (`where_in`), a query-builder method
   (`field.like()`), or a hook abstraction (`hook.get_records()`) that
   doesn't happen to be spelled `.execute()`/`.raw()`/`.extra()`/`text()`.
   This is arguably the single biggest gap found in this evaluation: popular
   frameworks build their own abstractions over the raw DB-API, and those
   abstractions use their own vocabulary (`.run()`, `.get_records()`,
   `.like()`, Jinja macros used inside larger templates) that inlet's fixed
   four-idiom list doesn't anticipate.
2. **Same-function resolution has a real hole beyond the documented wall.**
   The Archery case shows `_resolve_name` failing on a `try:`-nested
   assignment in the *same* function as the `.execute()` call — no
   cross-function tracing needed, just a level of block nesting the
   walker doesn't descend into. Given how common `try/except` is around DB
   code specifically (exactly the code inlet targets), this likely affects
   real code more often than the documented, tested cross-function wall
   does.
3. **The generic idiom is a name match with no receiver-type awareness.**
   peewee's `Query.execute(database)` and Django's
   `BaseCommand.execute(*args)` show that "any `.attr == 'execute'` call"
   sweeps in methods that are not database calls at all, simply because
   `execute` is a common verb. This doesn't cause false negatives on real
   SQLi, but it dilutes the `uncertain` bucket — in peewee, by roughly
   two-thirds — which matters for how usable the tool is in practice: a
   reviewer working through `--only concatenated,uncertain` on peewee would
   spend most of their time on findings that were never about a query
   string.

**Is `uncertain` doing its job?** Mixed, and the direction of the miscalibration
runs both ways depending on the case, which is itself worth stating plainly
rather than picking one story. It correctly and usefully flags real ambiguity
in records/dataset/SQLModel/Alembic (a DB call whose query text is a
parameter or a call result — exactly the honest "can't resolve this" case
the README describes). It is **too liberal** in peewee and Django management
commands, where a same-named-but-unrelated method inflates the bucket with
noise a human resolves in seconds. It is **too conservative** in the
SQLAlchemy `text(...).bindparams(...)` chain case and in the Archery
`try:`-nested case — both are genuinely concatenation-shaped and land in
`uncertain` only because of narrow unwrapping/resolution logic, not because
the ambiguity is real. Neither miscalibration is huge in volume, but both are
concrete and reproducible, and they point in opposite directions for the
same verdict bucket.

**Bottom line, stated as plainly as the fixture results:** the fixture suite
proves inlet correctly classifies each of the seven patterns it was written
to detect, and that result stands. Against code nobody wrote with inlet in
mind, it caught 0 of 5 documented historical SQLi bugs cleanly, surfaced 1 of
5 at the right line but the wrong (less urgent) verdict, and missed the
other 4 because the vulnerable code never took the textual shape inlet
watches for — not because the vulnerable *data flow* was hard to trace. On
the noise-floor side, its shape classification itself held up well (no
clear shape misfires found), but a meaningful fraction of `uncertain`
findings in real code are name collisions with non-SQL `.execute()` methods
rather than genuine query-string ambiguity. For a v0.1.0 tool with a
deliberately narrow, documented scope, this is a reasonable place to be — but
the specific failure modes here (idiom-name coverage, nested-block
resolution, receiver-type blindness) are gaps beyond what the README
currently documents, and are candidates for the next documented "wall" or
the next fix, respectively.

## 4. Limitations of this evaluation

- **Group A is small and not independent.** 5 packages, and 3 of the 4
  misses share the same root cause (idiom-name coverage). This is evidence
  of a pattern, not a statistically defensible miss rate — a differently
  selected Group A (e.g., biased toward small scripts with raw
  `cursor.execute(f"...")` calls rather than framework internals) would very
  plausibly show a much higher hit rate, precisely because Group A here was
  drawn from where *verifiable, well-documented* CVEs were findable, and
  that population skews toward large, well-governed projects with their own
  DB abstraction layers.
- **Group A was genuinely hard to fill.** Roughly 20+ candidate CVEs were
  searched before landing on 5 that (a) involved real string-built SQL and
  not ORM-parameter misuse, (b) had a public fix commit or advisory precise
  enough to locate the line independently, and (c) had a Python source tree
  still fetchable at the vulnerable version. Several strong-looking leads
  were dropped for failing (b) (e.g., Flask-AppBuilder's order-by SQLi has
  only a Snyk ID and no located fix commit) or, in pgAdmin 4's case, for not
  actually exercising a Python DB-execute call at all once the source was
  read (§1). This suggests documented, line-precise, string-building Python
  SQLi CVEs are less abundant than SQLi CVEs in general — most modern
  Python SQLi advisories describe ORM/query-builder parameter misuse, which
  is explicitly out of scope for what inlet claims to detect.
- **Sampling on the two largest Group B packages weakens precision, not
  direction.** The qualitative conclusions about SQLAlchemy and Django's
  `uncertain` buckets rest on partial coverage (§2). The specific bugs
  identified (peewee's naming collision, the `text().bindparams()` chain,
  Archery's `try:` nesting) are fully verified against source, independent
  of sampling — but claims like "the majority of concatenated hits are
  low-risk config interpolation" are extrapolated from a partial read and
  could shift with full coverage.
- **One evaluator, one pass, not blind.** No second reviewer checked the
  hit/miss/false-positive calls in this document. The line between "genuine
  risk shape" and "false positive" for the `concatenated` bucket in
  particular (e.g., Django's cache-table `table` name) involved a judgment
  call about typical deployment practice that a different reviewer could
  reasonably make differently.
- **This evaluation only tested `inlet scan` with default flags.** It did
  not exercise `--only`, the library API, or any code path other than
  directory scanning.

## 5. Post-fix delta (v0.1.1)

§3 identified two distinct problems. One was a fixable precision bug: the
`execute`/`raw`/`extra` idioms matched on method name alone, so peewee's
`Query.execute(database)` — where the argument is a `Database`/connection
object, not SQL, and the receiver is a query-builder object, not a cursor —
got swept in and reported as `uncertain`, inflating peewee's `uncertain`
bucket by roughly two-thirds. The other was a structural wall (idiom-name
coverage stopping at framework abstraction boundaries) that is **not**
addressed here — see the new "Walls" section in `README.md`.

**The fix.** `detectors.py` now records, for every `execute`/`raw`/`extra`
candidate, whether the receiver gives positive evidence of being a DB-API
cursor/connection or an ORM session: either an explicit `.cursor()` call in
the chain, or a receiver whose terminal name segment is one of a small,
spec-grounded set (`cursor`, `cur`, `curs`, `conn`, `con`, `connection`,
`session` — PEP 249's and SQLAlchemy's own vocabulary, not any one
package's). `core.py` then drops a finding only if *both* classify_expr
still came back `uncertain` *and* that receiver evidence is absent — never
for a `concatenated` or `parameterized` verdict, and never before
classification has had a chance to resolve a bare Name through the same
local-scope logic it always used. That ordering matters: an early
implementation that gated on the *unresolved* argument shape at detection
time broke Django's own `self.execute(sql)` pattern in
`schema.py` (`sql = "..." % {...}` assigned one line above, then
`self.execute(sql)`) — a real, previously-correct `concatenated` finding —
because `self` isn't a conventional cursor name and the syntactic argument
at the call site is a bare `Name`. That would have been exactly the kind of
regression Part 1 said to treat as disqualifying. The fix was to gate on
`classify_expr`'s output instead of the raw syntax, which is provably
equivalent to the intended rule for every existing fixture and closes that
hole; `tests/fixtures/self_execute_resolved_concat_risky.py` pins it down as
a regression test.

No idiom name and no package name appears in `_receiver_is_cursor_like`;
the two new exclusion fixtures
(`tests/fixtures/builder_execute_not_sql.py`,
`tests/fixtures/builder_execute_string_arg_risky.py`) and the true-positive
regression fixture above are the check that it stayed that way. All 7
original fixtures pass unchanged; 8 new tests were added (15 total, all
passing).

**Group B re-scanned, patched version, same 10 packages, same targets:**

| Package | uncertain before | uncertain after | net | concatenated before → after |
|---|---|---|---|---|
| SQLAlchemy | 421 | 394 | −27 | 26 → 26 (unchanged) |
| peewee | 33 | **9** | **−24** | 8 → 8 (unchanged) |
| records | 6 | 6 | 0 | 0 → 0 |
| dataset | 11 | 3 | −8 | 0 → 0 |
| SQLModel | 3 | 0 | −3 | 0 → 0 |
| aiosqlite | 2 | 2 | 0 | 3 → 3 (unchanged) |
| djangorestframework | 0 | 0 | 0 | 0 → 0 |
| Flask-SQLAlchemy | 4 | 4 | 0 | 0 → 0 |
| Alembic | 11 | 8 | −3 | 0 → 0 |
| Django (patched) | 81 | 23 | −58 | 76 → 76 (unchanged) |
| **Total** | **572** | **449** | **−123** | **113 → 113 (unchanged)** |

`concatenated` and `parameterized` counts are identical, package for
package, before and after — confirmed by diffing every finding line, not
just spot-checked. The fix, as designed, only ever removes `uncertain`
findings. records, aiosqlite, djangorestframework, and Flask-SQLAlchemy are
byte-for-byte identical output before and after (confirmed by diff, not
just matching counts).

**The peewee result, stated plainly:** every one of the 24 removed peewee
findings is the exact false-positive shape identified in §2/§3 —
`database.execute(self)`, `self.execute(database)`,
`self.database.execute(...)` (×10), `clone.execute(database)`,
`child_query.execute(database)`, and similar, all confirmed by diff to be
gone. Every one of the 9 remaining peewee `uncertain` findings is a real
`cursor.execute(...)`/`self.cursor().execute(...)`/`conn.execute(...)` call
with an unresolvable argument — confirmed by diff to be unchanged. No
peewee true positive was lost. This is the fix working exactly as
intended, on the exact package that motivated it.

**Did the rule drop real findings elsewhere? Yes — substantially, and this
needs to be said as plainly as the peewee result, not folded into a
footnote.** A full diff (not a sample — the counts were small enough to
enumerate completely) across all 10 packages found 99 removed findings
outside peewee. Of those, 5 (in Django's `management/` tree —
`createsuperuser.py`, `runserver.py`, `sqlmigrate.py`, `base.py`,
`core/management/__init__.py`) are the same category of bonus, correct
removal already noted in §2: Django's `BaseCommand.execute()` CLI dispatch,
unrelated to SQL, collided with the same name.

**The remaining 94 are real DB-execute call sites, not false positives,
lost as a side effect of the same rule:**

- **Django, 53 of the 58 removed:** `self.execute(sql)` /
  `schema_editor.execute(sql)` / `super().execute(...)` throughout
  `django/db/backends/*/schema.py` and `django/db/backends/base/schema.py`
  — Django's `SchemaEditor.execute()` is a real, thin wrapper around
  `self.connection.cursor().execute(sql, params)`, called from dozens of
  DDL methods (`add_field`, `alter_db_table`, etc.) as `self.execute(...)`.
  These are exactly the same real DB-execute calls documented as correctly
  `concatenated` in §2's Django review, just the ones whose argument
  didn't resolve to a string shape.
- **SQLAlchemy, 27 removed:** `self.execute(...)` inside `Engine`/`Session`/
  `Connection`'s own method bodies, plus `bind.execute`, `trans.execute`,
  `subject.execute`, `rec.execute`, `action.execute`,
  `self._proxied.execute` (async scoping proxies), and
  `connection.execution_options(...).execute(...)` (an `Attribute` chain
  whose immediate receiver is a `Call`, not a name, so it can't match
  either evidence rule). All real.
- **dataset, 8 removed:** `self.executable.execute(...)` /
  `self.db.executable.execute(...)` — dataset's own name for its wrapped
  SQLAlchemy `Engine`/`Connection`. Real.
- **SQLModel, 3 removed:** `super().execute(statement, ...)` — SQLAlchemy
  `Session.execute()`, called via `super()`, which has no receiver name at
  all to evaluate. Real (if already weak-signal: `statement` was a bare
  parameter, `uncertain` either way).
- **Alembic, 3 removed:** `cls.execute(...)`,
  `operations.migration_context.impl.execute(...)`,
  `self.get_context().execute(...)` — Alembic's actual "run this DDL"
  entry points. Real.

**Why this isn't a bug to patch further.** `self.execute(x)` is
syntactically identical whether `self` is Django's `SchemaEditor`,
SQLAlchemy's `Engine`, or peewee's `Query` — nothing in the AST at the call
site distinguishes "a thin wrapper around a real cursor" from "an unrelated
object that happens to define its own `execute` method." peewee's own false
positives use exactly the same receiver names this section's real losses
use (`self`, `database`) — `peewee.py:2210`'s `self.execute(database)` and
Django's `schema.py:167`'s `self.execute(sql)` are the same shape by every
signal available to single-file AST analysis. Broadening the convention
list to recover Django's `self`/`schema_editor` cases would readmit
peewee's `self.execute(database)` right back in; there is no name-based
line to draw between them. Resolving it for real would require knowing
what class `self` is bound to - interprocedural, type-aware analysis this
tool doesn't do, for the same reason described as out of scope in the
README's original scope-wall section.

**Net read on the trade.** The patch removes one confirmed, clean
false-positive category (24 peewee findings, 5 Django CLI-dispatch
findings — 29 total) at the cost of 94 real-but-already-weak-signal
`uncertain` findings elsewhere, concentrated in exactly the kind of
generic-receiver DB-wrapper method (`self.execute()`, `super().execute()`)
that turns out to be common across mature ORMs and frameworks, not just
peewee. Whether that trade is worth it depends on what a user does with
`uncertain` output: if `uncertain` is read as "worth a quick look," this
patch makes that bucket smaller and more precise in peewee specifically,
but meaningfully less complete in Django, SQLAlchemy, dataset, and Alembic.
This document does not resolve that judgment call in inlet's favor — it
reports the exact size and shape of the trade so a user (or a future
version) can.

**Group A is unchanged, deliberately.** The 5 CVE packages were not
re-scanned. None of the four misses documented in §2 involved the
`generic_execute`/`django_raw`/`django_extra` false-positive pattern this
patch addresses — three were idiom-coverage misses (`where_in`,
`field.like()`, `hook.get_records()` never call anything named `execute`/
`raw`/`extra`/`text` at all) and one (Django's `CVE-2022-28346`) was a
scope-wall miss unrelated to receiver naming. The Archery partial
(`CVE-2023-30556`, `oracle.py:1347`) was already `cursor.execute(...)` with
receiver `cursor` — squarely inside the convention list — so its
`uncertain` classification is unaffected by this patch; it remains
`uncertain` for the same `try:`-block resolution reason documented in §2,
not because of receiver evidence. Re-running Group A would not change any
of the five verdicts, and re-scanning it here would risk implying this
patch touched the structural wall, which it did not.

## 6. v0.1.1 → v0.1.2, a reverted attempt

This section is not a footnote to §5 — it's the more important outcome of
the two, and it's kept as its own labeled section rather than folded
quietly into the delta table above, because what got reverted and why
matters more than the numbers in either version.

**What v0.1.1 tried.** A candidate `.execute()`/`.raw()`/`.extra()` call
that `classify_expr` still resolved to `uncertain` was dropped from output
entirely — not reported at any verdict — unless the receiver gave positive
evidence of being a cursor, connection, or ORM session (an explicit
`.cursor()` call in the chain, or a name like `cursor`/`conn`/`session`).
The intent was narrow and the peewee result was clean: it removed exactly
24 confirmed false positives (`Query.execute(database)`-style calls, where
the argument is a connection object, never SQL) and changed nothing else
about peewee's output.

**What it broke.** The same rule, applied uniformly (as a *general*
AST-shape rule has to be — the whole point of avoiding package-specific
special-casing), also silently dropped 94 real DB-execute call sites across
the rest of Group B: Django's `SchemaEditor.execute()` (53 call sites,
`django/db/backends/*/schema.py`), SQLAlchemy's own `Engine`/`Session`/
scoping-proxy internals (27), `dataset`'s `self.executable.execute()` (8),
SQLModel's `super().execute()` (3), and Alembic's `cls.execute()`/
`operations.migration_context.impl.execute()`/`self.get_context().execute()`
(3). None of those are false positives. They're real, if already
low-confidence, `uncertain` findings that simply stopped existing in
`inlet`'s output — not downgraded, not deprioritized, gone. §5's original
writeup reported this size and shape honestly at the time, but reporting a
regression accurately is not the same as it being the right behavior to
ship, and on reflection it wasn't.

**Why it was reverted.** The two failure modes are not symmetric, and
v0.1.1 treated them as if they were. An `uncertain` finding that turns out
to be noise costs a reader a few seconds — they read the line, see it's
`self.execute(database)` inside a query builder, and move on. A finding
that was never reported costs nothing to the reader and everything to
whoever needed it: it cannot be dismissed, reconsidered, or found later by
grepping the output, because it was never there. `inlet` reporting
`self.execute(sql)` as `uncertain` on Django's `SchemaEditor` — sql
unresolved, no promises made — is exactly what §1 of this document's
"What this is not" section says `inlet` is for: a lead, not a verdict.
Silently excluding it is a stronger claim than `inlet` is positioned to
make: it asserts, with no real basis, that the call was safe to ignore.
That's an availability failure dressed up as a precision improvement.

This mirrors the fail-closed posture the rest of this tool collection
already takes — secfix won't claim "fixed" without proof, husk's timeout
kills a hung check rather than trusting it succeeded, witness names its
ctypes blind spot loudly instead of pretending coverage it doesn't have.
v0.1.1 was the same category of mistake in the opposite direction: it
traded visible, recoverable noise for confident, unrecoverable silence.
**The design principle, stated for future reference:** when a refinement's
only available lever is "exclude the finding when the evidence is
insufficient," that is not a lever this tool should pull, no matter how
clean the motivating case looks in isolation. Downgrading confidence is
fine. Removing the finding is not.

**The real, irreducible finding — stated plainly, because it's the
legitimate insight underneath the discarded fix.** `self.execute(x)` is
genuinely, structurally ambiguous from where `inlet` sits, and no amount of
tuning the receiver-name convention list fixes that. Django's
`SchemaEditor.execute()`, SQLAlchemy's `Engine.execute()`, and peewee's
`Query.execute()` are the *identical* AST shape: an attribute access named
`execute`, called with a non-string-shaped argument, on a receiver named
`self`. Nothing in the local syntax says which of those three `self`s wraps
a real DB cursor two calls down and which is an unrelated builder object.
Resolving it for real needs to know what class `self` is bound to —
interprocedural, type-aware analysis, the same category of thing already
named out of scope by the cross-function scope wall. This is not "a
heuristic that needs more tuning." It's a hard limit of single-file AST
analysis, and it belongs in `uncertain` — the verdict `inlet` already has
for exactly this situation — not in a bespoke exclusion path invented to
paper over it.

**The fix, mechanically.** `core.py`'s `scan()` no longer drops any
candidate based on `receiver_is_cursor_like`. Every `.execute()`/`.raw()`/
`.extra()` call that `find_candidates` identifies is now reported, at
whatever verdict `classify_expr` produces, exactly as in v0.1.0. The
receiver-evidence detection itself (`detectors._receiver_is_cursor_like`)
was kept, not deleted — it's still attached to every `Candidate` as
metadata, still exercised by its own unit tests, and still available for a
future *upgrade*-only use (e.g. surfacing high-confidence cursor evidence
to a reader some other way) — it is just never consulted to remove a
finding from output. The one part of v0.1.1 that *was* correct and stays:
the "argument resolution before evidence check" ordering fix, which was
needed to stop the gate (when it existed) from short-circuiting Django's
`self.execute(sql)` where `sql` resolves via a straight-line `%`-format
assignment one line up — `tests/fixtures/self_execute_resolved_concat_risky.py`
still pins that down and still passes.

`tests/fixtures/builder_execute_not_sql.py` (the peewee-shaped fixture) was
rewritten in place rather than deleted: it now asserts both calls come back
`uncertain`, not that they're excluded. A new fixture,
`tests/fixtures/self_execute_unresolvable_uncertain.py`, models the other
side directly — a genuine `SchemaEditor`-style DB wrapper with the same
ambiguous shape — and asserts the same `uncertain` outcome, so the test
suite pins down that both the false-positive-shaped and the
true-positive-shaped versions of "generic receiver, unresolvable argument"
land in the same honest place. 16 tests total, all passing; nothing from
v0.1.0 or the valid part of v0.1.1 changed.

**Group B re-scanned again, same 10 packages, same targets, v0.1.2:**

| Package | uncertain (v0.1.0) | uncertain (v0.1.1) | uncertain (v0.1.2) |
|---|---|---|---|
| SQLAlchemy | 421 | 394 | **421** |
| peewee | 33 | 9 | **33** |
| records | 6 | 6 | **6** |
| dataset | 11 | 3 | **11** |
| SQLModel | 3 | 0 | **3** |
| aiosqlite | 2 | 2 | **2** |
| djangorestframework | 0 | 0 | **0** |
| Flask-SQLAlchemy | 4 | 4 | **4** |
| Alembic | 11 | 8 | **11** |
| Django (patched) | 81 | 23 | **81** |
| **Total** | **572** | **449** | **572** |

**Report the actual peewee number plainly, without rounding toward either
side: it's 33 — identical to v0.1.0, not something in between 9 and 33.**
That's worth explaining rather than leaving as a surprising-looking result.
The only mechanism that ever produced a confident `parameterized`/
`concatenated` verdict was, and still is, `classify_expr` resolving the
*argument* — a literal, an f-string, a `%`/`+`/`.format()` expression, or a
Name that resolves to one of those in local scope. That mechanism was never
touched by either the v0.1.1 patch or this revert; receiver naming was
never part of it and still isn't. "Keep the receiver-evidence signal as an
upgrade path" does not mean invented behavior where a cursor-like receiver
name promotes an otherwise-unresolvable argument to a confident verdict —
there's no principled basis for that (a `cursor`-named receiver says
nothing about what an unresolvable argument actually contains), and adding
it would be fabricating precision `inlet` doesn't have. With no such
mechanism added, v0.1.2's classification behavior is, correctly, identical
to v0.1.0's. A full diff (every finding line, not just the counts)
confirms all 10 packages' output in v0.1.2 is byte-for-byte identical to
the original pre-v0.1.1 baseline in §2. The 94 findings v0.1.1 dropped —
Django's `SchemaEditor.execute()`, SQLAlchemy's `Engine`/`Session`
internals, `dataset`'s `self.executable.execute()`, SQLModel's
`super().execute()`, Alembic's DDL entry points — are confirmed back in
the output as `uncertain`. peewee's 24 originally-misleading findings are
also back as `uncertain` — visible again, exactly as intended: recoverable
noise instead of unrecoverable silence, for everyone, not just for peewee.

`concatenated` and `parameterized` counts are unaffected in every version
of this story (v0.1.0, v0.1.1, and v0.1.2 all agree on them) — this was
never about those two verdicts. The entire episode is contained to how
`uncertain` candidates are reported, and v0.1.2 reports all of them.

## §7: Reference comparison — Semgrep on the same corpus

Everything above measures `inlet` in isolation. A 0/5 CVE-hit rate and a
false-positive count on Group B mean nothing to a reader without something
to compare them against. This section runs Semgrep — a widely-used,
community-maintained static analysis tool, not a competitor `inlet` is
trying to beat — against the identical 15-package corpus from §1–§2, using
its current public registry rulesets, and reports the comparison exactly
as it came out. No claim below is asserted without the underlying Semgrep
output having been read in this session, the same standard §1 sets for the
CVE claims themselves.

### Methodology and a registry-drift finding worth stating up front

Semgrep 1.177.0, unauthenticated CLI, run on 2026-09-12/13. The task
suggested checking Semgrep's *current* registry rather than assuming rule
names from memory — that check turned up something worth reporting before
any corpus results: naively running the two packs an informed guess would
reach for first, `p/python` and `p/sql-injection`, against a plain
`cursor.execute(f"SELECT * FROM t WHERE name = '{name}'")` probe (no
Django/Flask/SQLAlchemy involved) produces **zero findings** under either
pack alone, unauthenticated. That is not because those packs are empty —
fetching their actual rule manifests from `https://semgrep.dev/c/p/python`
confirms both nominally contain multiple SQL-injection rules — but because
those rules are framework/driver-specific (Django `.raw()`/`.extra()`,
Flask/SQLAlchemy taint sources) and none of them match a bare,
un-frameworked `.execute()` call. The one rule that *would* catch that
shape,
`python.lang.security.audit.formatted-sql-query.formatted-sql-query`, is
absent from `p/python`'s and `p/sql-injection`'s active rule set entirely;
it lives in `p/bandit` and `p/default`. Similarly,
`python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query`
is only in `p/default` among the packs checked. Verified directly:
fetching all eight candidate packs' raw YAML and grepping rule IDs,
cross-checked against which rules actually fired on targeted probes for
each framework shape (Django `.raw()`/`.extra()`, SQLAlchemy `text()`).

**Consequence for method:** this evaluation runs the union of seven packs
— `p/python`, `p/security-audit`, `p/sql-injection`, `p/django`,
`p/flask`, `p/bandit`, `p/default` — rather than the two names an informed
guess reaches for first, specifically because no single commonly-suggested
pack name covers the SQL-injection-relevant rules this corpus needs.
Results below are filtered to a 23-rule allowlist of the SQL-injection-
specific rule IDs actually present across those seven packs' manifests —
see [`semgrep_reference/sql_rule_allowlist.txt`](semgrep_reference/sql_rule_allowlist.txt)
for the full list and [`semgrep_reference/findings_by_package.txt`](semgrep_reference/findings_by_package.txt)
for every allowlisted finding, per package, that this section's numbers
are drawn from — excluding two `python.sqlalchemy.performance.*` rules
that share the "sql" substring but are performance advice, not security
findings. `p/default`'s remaining
~1050 rules (crypto, XSS, Terraform, other languages) were left enabled
during the scan — harmless, since they don't match Python SQL shapes —
and excluded post-hoc by the allowlist rather than by a narrower
`--config`, so the filtering step itself is inspectable rather than baked
into an opaque command line.

**A second, more consequential methodology finding, also from checking
actual behavior rather than assuming it:** Semgrep's bundled default
`.semgrepignore` silently excludes `tests/`-named directories from a
directory scan, with no warning printed unless `--verbose` is passed. This
was caught, not assumed: an initial pass produced zero findings in
aiosqlite, where §2's inlet review documented 3 `concatenated` hits, all
three inside `aiosqlite/tests/perf.py` and `aiosqlite/tests/smoke.py`.
`inlet scan` applies no such exclusion — its LOC-scanned totals in §2
already include test trees (Django's 130K+ LOC figure would be
impossible otherwise). Comparing a tool that scans test code against one
that's silently skipping it would be a corpus mismatch, not a tool
comparison. Fixed by passing the (internal/experimental, but verified
directly) `--x-ignore-semgrepignore-files` flag, confirmed before and
after via aiosqlite's scanned-file count (5 → 10 files) and finding count
(0 → 6 in the SQL-relevant allowlist, exactly matching the 3 test-file
lines already known from §2 plus 3 more from the broader rule union). All
results below use this flag, on all 15 packages.

**Hit / miss / partial** uses the same definitions as §1: a hit lands
Semgrep output on the specific verified vulnerable line; a miss produces
no finding anywhere near it; a partial would be a finding on the right
line carrying a materially weaker signal. Semgrep has no verdict-downgrade
mechanism analogous to inlet's `uncertain`, so "partial" only applies here
if a real quality difference shows up in practice — see Archery, below.

### Group A results

| Package | CVE | inlet verdict (§2) | Semgrep hit/miss | Notes |
|---|---|---|---|---|
| Django 3.2.12 | CVE-2022-28346 | MISS | **MISS** | Zero findings within several lines of `django/db/backends/utils.py:82/84` (the generic execute call inlet also only reached generically) or the alias-check region of `query.py`/`compiler.py`. Nearby `custom-expression-as-sql`/`avoid-raw-sql` hits in `compiler.py`/`query.py` (query.py:273, query.py:1080) are unrelated `sql % params` plumbing, confirmed by reading the flagged lines directly — not the alias-injection logic. |
| Apache Superset 2.1.2 | CVE-2023-49736 | MISS | **MISS** | Zero findings anywhere in `superset/jinja_context.py`. Same root cause as inlet: `where_in` never calls anything spelled `execute`/`raw`/`extra`/`text`, and none of Semgrep's rules key on hand-rolled string-quoting helper functions either. |
| Tortoise ORM 0.16.5 | CVE-2020-11010 | MISS | **MISS** | Zero findings in `tortoise/filters.py`. The only findings in the whole package are two unrelated f-string `PRAGMA` statements in `backends/*/client.py`. `field.like()` never reaches a recognized call, same as for inlet. |
| Archery 1.9.0 | CVE-2023-30556 | PARTIAL (right line, downgraded to `uncertain`) | **HIT** | `sql/engines/oracle.py:1347` (`cursor.execute(create_task_sql)`) is flagged by `formatted-sql-query` (WARNING) and `sqlalchemy-execute-raw-query` (ERROR, mislabeled — Archery doesn't use SQLAlchemy, but the shape match is correct). No verdict downgrade: Semgrep pattern-matches the f-string-into-`.execute()` shape directly and isn't defeated by the `try:`-block nesting that broke inlet's same-function name resolution here (§2's documented Wall-adjacent bug). |
| Airflow common-sql provider 1.24.0 | CVE-2025-30473 | MISS | **MISS** | Literally zero findings of any kind, any rule, anywhere in the package. `hook.get_records()` never calls anything named `execute`/`raw`/`extra`/`text`, and no Semgrep rule in the seven-pack union keys on Airflow's DB-hook vocabulary either. |

**Semgrep: 1 hit, 0 partial, 4 misses, out of 5 — inlet: 0 hits, 1
partial, 4 misses.** The headline number moves by exactly one case
(Archery), and it moves because of a mechanism difference, not a coverage
difference: Semgrep isn't attempting inlet's kind of local-scope name
resolution at all, so it has nothing for a `try:` block to defeat. On the
other four — the ones that matter more, because they're where idiom-name
coverage rather than a resolution bug is the actual wall — **Semgrep
misses the identical four CVEs `inlet` misses, for the identical
underlying reason**: Django, Superset, Tortoise, and Airflow all route the
vulnerable string through a framework abstraction (`SQLCompiler`,
a Jinja macro, `field.like()`, `hook.get_records()`) that is never spelled
`execute`/`raw`/`extra`/`text` at the point the injection actually
happens, or — Django's case specifically — assembles the vulnerable value
across enough functions and files that no single-file, non-interprocedural
tool was ever going to reach it. This is stated plainly because it's the
single most load-bearing finding in this section: `inlet`'s README names
"idiom-name coverage" as Wall 2 and treats it as `inlet`'s own documented
limit. A ruleset built and maintained by a much larger team, over years,
hits the *same* wall on the *same* four real-world CVEs. That doesn't
excuse `inlet`'s gap — but it reframes it: this isn't a gap `inlet`
specifically failed to close, it's a shared, structural blind spot of
pattern/AST-based SQL-injection detection in general, once the vulnerable
code lives inside a framework's own abstraction over "run this SQL."

### Group B results — noise-floor comparison

Semgrep has no `uncertain`-equivalent category — every finding it reports
is a confident pattern match at whatever severity the rule carries; there
is no "I see a DB call here but can't resolve the query text" signal. That
makes a clean side-by-side count somewhat apples-to-oranges, flagged here
rather than smoothed over:

| Package | inlet `concatenated` / `uncertain` (current, §2/§6) | Semgrep SQL-relevant findings (allowlisted) | Notes |
|---|---|---|---|
| SQLAlchemy | 26 / 421 | 49 | Roughly 2× inlet's `concatenated` count, a small fraction of `concatenated`+`uncertain`. See discussion below. |
| peewee | 8 / 33 | 16 | Comparable order of magnitude to inlet's real signal once the ~24 naming-collision false positives §2/§5 already identified are set aside. |
| records | 0 / 6 | **0** | Semgrep silent; inlet's 6 `uncertain` findings are the confirmed-real `self._conn.execute(text(query).bindparams(**params))` pattern (§2) — a genuine DB call whose text is a function parameter. |
| dataset | 0 / 11 | **0** | Same shape as records: `self.executable.execute(...)` with an unresolvable argument. Semgrep has no rule that fires on an unresolved-argument `.execute()` call absent a recognized taint source. |
| SQLModel | 0 / 3 | **0** | `super().execute(statement, ...)` — no receiver name, no taint source Semgrep's rules recognize. |
| aiosqlite | 3 / 2 | 6 | The 6 are the *same 3 lines* as inlet's 3 `concatenated` hits (`tests/perf.py:174`, `:187`, `tests/smoke.py:459`), each matched twice — once by `formatted-sql-query`, once by `sqlalchemy-execute-raw-query` (mislabeled; aiosqlite doesn't use SQLAlchemy). Not 6 independent findings. Neither tool found anything at `aiosqlite/core.py`'s two genuinely `uncertain` lines. |
| djangorestframework | 0 / 0 | 4 | 2 lines (`tests/conftest.py:151`, `:156`), each matched twice by the same rule pair as aiosqlite above — not DRF's own filtering/ordering code. Both tools agree DRF's actual library code has zero raw-SQL surface. |
| Flask-SQLAlchemy | 0 / 4 | **0** | Same "unresolved argument, no taint source" gap as records/dataset/SQLModel. |
| Alembic | 0 / 11 | 9 | All 9 are inside `tests/`, not Alembic's own DDL entry points (`cls.execute()`, `operations.migration_context.impl.execute()`) that §5/§6 identified as inlet's real (if low-confidence) `uncertain` findings — Semgrep found none of those. |
| Django (patched) 5.1.3 | 76 / 81 | 443 | Roughly 3× inlet's `concatenated`+`uncertain` combined. Dominated by `custom-expression-as-sql` (171 hits) in `compiler.py`'s SQL-expression-node classes, `sqlalchemy-execute-raw-query` (150, all mislabeled — Django doesn't use SQLAlchemy), `formatted-sql-query` (72), and `avoid-raw-sql` (50) — not manually reviewed to the same per-finding depth §2 applied to inlet's Django sample; reported as a raw count, not audited as a false-positive rate the way §2's inlet numbers were. |

**The one clear, consistent pattern across Group B: for four packages
(records, dataset, SQLModel, Flask-SQLAlchemy) Semgrep reports nothing at
all, while inlet's `uncertain` bucket reports a combined 24 findings that
§2 already manually confirmed are real DB-execute call sites, not noise.**
This isn't inlet finding a vulnerability Semgrep missed — none of those 24
are confirmed exploitable, and inlet doesn't claim they are either. It's a
structural consequence of what each tool's rule model even attempts:
Semgrep's non-taint rules require the query text to be syntactically
visible (a literal, f-string, `%`-format, or concatenation) *at the call
site*; when it's a bare parameter or attribute access, there is nothing
for a pattern rule to match, and none of these four packages hand Semgrep
a recognized taint source (`request.*`, a named DB driver call) to chain
through instead. `inlet`'s `uncertain` verdict exists specifically to
report exactly this case — "real DB call, can't resolve the argument" —
as an honest, visible lead rather than staying silent. On this corpus,
that category is doing real, non-overlapping work no Semgrep rule in the
seven-pack union attempts.

The reverse also holds, and is worth naming with equal weight: Semgrep's
`avoid-sqlalchemy-text` rule fires on *any* `sqlalchemy.text()` usage as a
blanket "avoid this API" style warning, regardless of whether the call is
safely parameterized via `.bindparams()` — a coarser signal than inlet's
`concatenated`/`parameterized` distinction, which specifically separates
safe from risky `text()` usage rather than flagging the API itself. Some
of Semgrep's counts above include this style-level signal, not a
concatenation finding; inlet's `concatenated` bucket does not have an
equivalent category and would not count a safely-parameterized `text()`
call at all.

### Structural differences worth naming, beyond the numbers

- **Confidence model.** Semgrep findings carry a severity
  (INFO/WARNING/ERROR) assigned per-rule by the rule's author; inlet's
  verdicts (`parameterized`/`concatenated`/`uncertain`) are assigned per
  call site by what could and couldn't be locally resolved. These answer
  different questions — "how bad is this pattern, in general" vs. "could
  I tell what this specific expression actually is" — and neither
  subsumes the other.
- **Taint vs. shape.** A meaningful fraction of Semgrep's nominal Python
  SQLi rules (the Flask/Django/AWS-Lambda `tainted-sql-string` family) are
  taint-tracking rules keyed on a web-request or event-payload source
  reaching a SQL sink. That's a different, complementary detection
  strategy from both inlet's and Semgrep's own shape-based rules
  (`formatted-sql-query`, `sqlalchemy-execute-raw-query`) — and it is
  structurally unable to fire on library-internal code with no
  `request`/event object in scope, which is most of this corpus. This
  corpus, being mostly ORM/driver internals rather than application view
  code, does not exercise Semgrep's taint rules in a way that's fair to
  either count for or against them.
- **Cross-function reach.** Neither tool solved Django's CVE-2022-28346,
  and for the same practical reason — the vulnerable value crosses
  several functions and files before reaching a recognizable sink. Semgrep
  *can* do cross-file/interfile taint analysis (`--pro`, paid tier, not
  exercised here since the task scope is the public ruleset), which is a
  capability inlet has no plans to build (README's "Walls" section). This
  evaluation used the free/public CLI only, per the task's own framing —
  a paid or Pro-enabled Semgrep run might close some of this specific gap;
  that was not tested.
- **No fuzzy/behavioral verification in either tool.** Both tools are
  static and pattern/rule-based; neither executes code or proves
  exploitability. This evaluation does not compare either tool against an
  execution-based approach.

### Fairness caveats, stated plainly

- **Maintenance-effort asymmetry.** Semgrep's public registry rules are
  written and maintained by many contributors over several years; `inlet`
  is a single-author v0.1.0 built in about a week. That Semgrep *also*
  misses the same four Group A CVEs is more informative because of this
  gap, not despite it — but the gap itself means a "tie" on Group A is not
  a neutral result: it took `inlet` a week to reach parity with a
  much older, more resourced project on this specific slice, and Semgrep
  still has categories (taint tracking, a much broader idiom vocabulary,
  Pro-tier interfile analysis) that `inlet` doesn't attempt at all.
- **Unauthenticated CLI only.** This run did not use `semgrep login`. Per
  the rulesets' own on-screen messaging ("need more rules? `semgrep login`
  for additional free Semgrep Registry rules"), an authenticated free
  account may unlock rules not exercised here. This evaluation did not
  create or use a Semgrep account, so this ceiling is unverified in
  either direction — stated as an open question, not assumed answered.
- **Rule-set selection was a judgment call, made transparent, not
  hidden.** The seven-pack union and the 23-rule post-hoc allowlist were
  arrived at empirically (per the registry-drift finding above) rather
  than picked from a single canonical "the" Semgrep SQLi config, because
  no single commonly-suggested pack name covers this corpus's needs. A
  different, equally defensible selection could shift the Group B counts;
  the Group A hit/miss results (checked against specific known lines, not
  aggregate counts) are far less sensitive to this choice.
- **Depth of manual review is not equal.** §2's inlet numbers rest on
  every `concatenated` finding being read in full (or, for the two
  largest packages, read to a documented point of coverage). This
  section's Semgrep numbers are reported as raw allowlisted counts,
  cross-checked against specific known lines for Group A, but not
  manually read finding-by-finding for Group B the way §2 did for inlet.
  Django's 443 in particular should be read as "here is the number," not
  "here is the false-positive rate" — that would require the same
  per-finding review §2 gives inlet, which this section does not claim to
  have done.
- **`inlet`'s `uncertain` category has no Semgrep equivalent, in either
  direction.** It is real signal Semgrep's rule model doesn't attempt
  (records/dataset/SQLModel/Flask-SQLAlchemy, above) — but it is also,
  per §3/§5's own honest accounting, sometimes noise (peewee's naming
  collisions). Crediting `inlet` for the records/dataset/SQLModel result
  without also carrying forward §3's own finding that the same category
  is inflated by non-SQL `.execute()` name collisions elsewhere would be
  cherry-picking inlet's better result and burying its own documented
  weakness in the same bucket.

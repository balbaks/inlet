# Semgrep reference-comparison artifacts

Supporting evidence for `EVALUATION.md` §7. Not raw Semgrep JSON (multi-MB
per package, mostly irrelevant non-Python/non-SQL findings from `p/default`'s
~1050 other rules) — these are the allowlist-filtered, human-readable
findings actually used to write §7's tables and claims.

- **`sql_rule_allowlist.txt`** — the 23 Python SQL-injection-relevant rule
  IDs, collected by fetching the raw rule manifests of all seven packs used
  (`https://semgrep.dev/c/p/<pack>`) and grepping for `sql` in Python rule
  IDs, then manually excluding two `python.sqlalchemy.performance.*` rules
  that share the substring but are performance advice, not security
  findings.
- **`findings_by_package.txt`** — for each of the same 15 packages/versions
  used in §1–§2, every Semgrep finding whose `check_id` is in the allowlist
  above, with file, line, severity, and rule ID. Paths are relative to the
  same `groupA/`/`groupB/` layout §1's corpus uses.

## Exact command

```console
semgrep scan \
  --config p/python --config p/security-audit --config p/sql-injection \
  --config p/django --config p/flask --config p/bandit --config p/default \
  --include '*.py' --x-ignore-semgrepignore-files --metrics=off --json \
  -o <package>.json <package-dir>
```

Semgrep 1.177.0, unauthenticated CLI, run 2026-09-12/13.

`--x-ignore-semgrepignore-files` is required for parity with `inlet scan`:
Semgrep's bundled default `.semgrepignore` silently excludes `tests/`
directories from a directory scan otherwise, and `inlet scan` applies no
such exclusion (see §7's methodology note for how this was caught, not
assumed).

`--config` is a 7-pack union, not one canonical "the SQLi pack," because
no single commonly-suggested pack (`p/python`, `p/sql-injection` alone)
carries all the SQL-injection-relevant rules found across the eight
candidate packs checked — see §7's registry-drift finding.

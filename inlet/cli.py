import argparse
import sys

from .core import scan

VERDICT_ORDER = ["concatenated", "uncertain", "parameterized"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="inlet", description="Map database-access call sites and classify their risk shape.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="scan a file or directory")
    scan_parser.add_argument("path", help="file or directory to scan")
    scan_parser.add_argument(
        "--only",
        help="comma-separated verdicts to show (parameterized,concatenated,uncertain)",
        default=None,
    )

    args = parser.parse_args(argv)

    if args.command == "scan":
        findings = scan(args.path)
        only = set(args.only.split(",")) if args.only else None

        by_verdict: dict[str, list] = {v: [] for v in VERDICT_ORDER}
        for finding in findings:
            by_verdict.setdefault(finding.verdict, []).append(finding)

        shown = 0
        for verdict in VERDICT_ORDER:
            group = by_verdict.get(verdict, [])
            if only is not None and verdict not in only:
                continue
            if not group:
                continue
            print(f"\n{verdict.upper()} ({len(group)})")
            for f in group:
                print(f"  {f.file}:{f.line}  {f.call}")
                print(f"    {f.snippet}")
            shown += len(group)

        if shown == 0:
            print("No matching findings.")

    return 0


if __name__ == "__main__":
    sys.exit(main())

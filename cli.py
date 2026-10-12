"""CLI companion. Examples: py cli.py, py cli.py --review-only --export evidence.csv"""
from __future__ import annotations

import argparse
from app import get_sample_connections
from netstat_monitor import export_csv, get_live_connections


def main():
    parser = argparse.ArgumentParser(description="Established TCP connection / IP review (Windows netstat -ano)")
    parser.add_argument("--review-only", action="store_true", help="Show only flagged connections")
    parser.add_argument("--demo", action="store_true", help="Use synthetic test data, no live netstat scan")
    parser.add_argument("--export", metavar="FILE.csv", help="Export all connections from snapshot to CSV")
    args = parser.parse_args()
    try:
        data = get_sample_connections() if args.demo else get_live_connections()
    except Exception as exc:
        parser.exit(status=1, message=f"Unable to scan: {exc}\n")
    rows = [c for c in data if c.risk == "Review"] if args.review_only else data
    print(f"{'FLAG':8} {'REMOTE IP':39} {'R.PORT':7} {'PID':>7} {'PROCESS':22} REASON")
    print("-" * 120)
    for c in rows:
        print(f"{c.risk:8} {c.remote_ip:39.39} {c.remote_port:<7} {c.pid:>7} {c.process:22.22} {c.reason}")
    print(f"\n{len(data)} established connections; {sum(c.risk == 'Review' for c in data)} flagged for context review.")
    if args.export:
        export_csv(args.export, data)
        print(f"Saved full snapshot to {args.export}")


if __name__ == "__main__":
    main()

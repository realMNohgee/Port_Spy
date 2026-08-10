#!/usr/bin/env python3
"""Port_Spy — Local port scanner. See what's listening, mapped to PIDs and process names. Zero deps."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from typing import Any

KNOWN_SERVICES: dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP Alt (dev)",
    8080: "Alt HTTP",
    8443: "Alt HTTPS",
    27017: "MongoDB",
    3000: "Node / Dev",
    5000: "Flask / Dev",
    4000: "Node / Dev",
    9090: "Prometheus / Dev",
    9200: "Elasticsearch",
    9092: "Kafka",
}


def _run_lsof() -> list[dict[str, Any]]:
    """Run `lsof -i -P -n` and parse the output into structured records."""
    try:
        result = subprocess.run(
            ["lsof", "-i", "-P", "-n"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except FileNotFoundError:
        sys.exit("Error: 'lsof' not found. Port_Spy requires lsof (macOS/Linux).")
    except subprocess.TimeoutExpired:
        sys.exit("Error: lsof timed out.")

    lines = result.stdout.strip().split("\n")
    if len(lines) < 2:
        return []

    records: list[dict[str, Any]] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        record = _parse_lsof_line(line)
        if record:
            records.append(record)
    return records


def _parse_lsof_line(line: str) -> dict[str, Any] | None:
    """Parse a single lsof output line into a dict."""
    parts = line.split()
    if len(parts) < 9:
        return None

    command = parts[0]
    pid_str = parts[1]
    user = parts[2]
    # fd = parts[3]
    # lsof columns: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
    # TYPE is typically IPv4/IPv6, protocol (TCP/UDP) is column 8 (parts[7])
    name = " ".join(parts[8:])

    # Extract port and protocol from NAME field
    # NAME looks like: *:8080 (LISTEN), 127.0.0.1:5432->127.0.0.1:5432 (ESTABLISHED),
    # or just *:8080
    port_match = re.search(r"[.:](\d{1,5})(?:\s|$|\))", name)
    proto_match = re.search(r"(TCP|UDP)", parts[7], re.IGNORECASE)

    if not port_match or not proto_match:
        return None

    port = int(port_match.group(1))
    proto = proto_match.group(1).upper()

    # Determine state from name field - check for (LISTEN) or other states AFTER the address
    state = "UNKNOWN"
    # More robust: find the last parenthesized token in the name
    state_match = re.findall(r"\(([^)]+)\)", name)
    if state_match:
        state = state_match[-1]
    else:
        # Check for *:PORT pattern which usually means LISTEN
        if re.match(r"\*:\d+", name.strip()):
            state = "LISTEN"
        elif "->" in name:
            state = "ESTABLISHED"

    try:
        pid = int(pid_str)
    except ValueError:
        pid = 0

    return {
        "port": port,
        "proto": proto,
        "pid": pid,
        "process": command,
        "state": state,
        "user": user,
        "name": name,
    }


def _format_text(records: list[dict[str, Any]]) -> str:
    """Format records as aligned text table."""
    if not records:
        return "No listening ports found."

    headers = ["PORT", "PROTO", "PID", "PROCESS", "STATE"]
    rows: list[list[str]] = []
    for r in records:
        rows.append([
            str(r["port"]),
            r["proto"],
            str(r["pid"]),
            r["process"],
            r["state"],
        ])

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(cell))

    lines: list[str] = []
    header_line = "  ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    lines.append(header_line)
    lines.append("-" * len(header_line))

    for row in rows:
        line = "  ".join(cell.ljust(col_widths[i]) for i, cell in enumerate(row))
        lines.append(line)

    return "\n".join(lines)


def _output(records: list[dict[str, Any]], fmt: str) -> None:
    """Output records in text or json format."""
    if fmt == "json":
        print(json.dumps(records, indent=2))
    else:
        print(_format_text(records))


def _filter_records(
    records: list[dict[str, Any]],
    port: int | None = None,
    proto_filter: str | None = None,
) -> list[dict[str, Any]]:
    """Filter lsof records by port and/or protocol."""
    filtered = records
    if port is not None:
        filtered = [r for r in filtered if r["port"] == port]
    if proto_filter and proto_filter != "all":
        filtered = [r for r in filtered if r["proto"] == proto_filter.upper()]
    # Only show LISTEN entries by default for scan
    return filtered


def cmd_scan(args: argparse.Namespace) -> None:
    """Handle the scan subcommand."""
    records = _run_lsof()

    proto_filter = None
    if args.tcp:
        proto_filter = "TCP"
    elif args.udp:
        proto_filter = "UDP"
    elif args.all:
        proto_filter = "all"
    else:
        proto_filter = "all"  # default: show all

    results = _filter_records(records, port=args.port, proto_filter=proto_filter)
    _output(results, args.format)


def cmd_lookup(args: argparse.Namespace) -> None:
    """Handle the lookup subcommand."""
    records = _run_lsof()
    port = args.port

    matches = [r for r in records if r["port"] == port]

    service = KNOWN_SERVICES.get(port, "Unknown")

    if args.format == "json":
        output_data: dict[str, Any] = {
            "port": port,
            "service": service,
            "processes": matches,
        }
        # Add full command info if available
        for m in output_data["processes"]:
            if m["pid"] > 0:
                try:
                    with open(f"/proc/{m['pid']}/cmdline", "r") as f:
                        cmdline = f.read().replace("\0", " ").strip()
                        m["cmdline"] = cmdline
                except (FileNotFoundError, PermissionError):
                    m["cmdline"] = m["process"]
            else:
                m["cmdline"] = m["process"]
        print(json.dumps(output_data, indent=2))
    else:
        print(f"Port {port} — {service}")
        print("-" * 40)
        if not matches:
            print("  Not currently in use.")
        else:
            for m in matches:
                cmdline = m["process"]
                if m["pid"] > 0:
                    try:
                        with open(f"/proc/{m['pid']}/cmdline", "r") as f:
                            cmdline = f.read().replace("\0", " ").strip()
                    except (FileNotFoundError, PermissionError):
                        cmdline = m["process"]
                print(f"  Process:  {m['process']} (PID: {m['pid']}, User: {m['user']})")
                print(f"  Command:  {cmdline}")
                print(f"  State:    {m['state']}")
                print(f"  Address:  {m['name']}")
                print()


def cmd_watch(args: argparse.Namespace) -> None:
    """Handle the watch subcommand — live monitor port changes."""
    interval = args.interval
    previous: set[tuple[int, str, int]] = set()  # (port, proto, pid)

    print(f"Port_Spy watching every {interval}s (Ctrl+C to stop)...")
    print()

    try:
        while True:
            records = _run_lsof()
            current: set[tuple[int, str, int]] = set()
            current_map: dict[tuple[int, str, int], dict[str, Any]] = {}

            for r in records:
                key = (r["port"], r["proto"], r["pid"])
                current.add(key)
                current_map[key] = r

            if previous:
                new_ports = current - previous
                closed_ports = previous - current

                timestamp = time.strftime("%H:%M:%S")
                for key in sorted(new_ports):
                    r = current_map[key]
                    print(f"[{timestamp}] NEW    {r['proto']:>4} :{r['port']:<6} → {r['process']} (PID: {r['pid']})")
                for key in sorted(closed_ports):
                    # Use the previous record's info for closed ports
                    prev_info = next((rec for rec in records if (rec["port"], rec["proto"], rec["pid"]) == key), None)
                    proc_name = prev_info["process"] if prev_info else "?"
                    print(f"[{timestamp}] CLOSED {key[1]:>4} :{key[0]:<6} ← {proc_name} (PID: {key[2]})")

            previous = current
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopped watching.")


def _add_format_arg(parser: argparse.ArgumentParser) -> None:
    """Add the shared --format argument."""
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for port_spy."""
    parser = argparse.ArgumentParser(
        description="Port_Spy — Local port scanner. See what's listening, mapped to PIDs and process names.",
        prog="port_spy",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    scan_p = sub.add_parser("scan", help="Scan listening ports")
    scan_p.add_argument("--port", type=int, help="Filter by port number")
    group = scan_p.add_mutually_exclusive_group()
    group.add_argument("--tcp", action="store_true", help="TCP only")
    group.add_argument("--udp", action="store_true", help="UDP only")
    group.add_argument("--all", action="store_true", help="All protocols")
    _add_format_arg(scan_p)

    # lookup
    lookup_p = sub.add_parser("lookup", help="Detailed info for a port")
    lookup_p.add_argument("port", type=int, help="Port number to look up")
    _add_format_arg(lookup_p)

    # watch
    watch_p = sub.add_parser("watch", help="Live monitor port changes")
    watch_p.add_argument(
        "--interval",
        type=float,
        default=3.0,
        help="Polling interval in seconds (default: 3)",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "lookup":
        cmd_lookup(args)
    elif args.command == "watch":
        cmd_watch(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

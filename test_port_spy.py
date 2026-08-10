"""Tests for Port_Spy CLI."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from io import StringIO
from unittest.mock import patch

# Add parent dir for import
sys.path.insert(0, ".")
from port_spy import (
    KNOWN_SERVICES,
    _filter_records,
    _format_text,
    _output,
    _parse_lsof_line,
    build_parser,
)


class TestParseLsofLine(unittest.TestCase):
    """Test _parse_lsof_line with various lsof output formats."""

    def test_listen_tcp(self):
        line = "com.dock 1234 legionsmacbook   18u  IPv4 0x...      0t0     TCP *:8080 (LISTEN)"
        result = _parse_lsof_line(line)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["port"], 8080)
        self.assertEqual(result["proto"], "TCP")
        self.assertEqual(result["pid"], 1234)
        self.assertEqual(result["process"], "com.dock")
        self.assertEqual(result["state"], "LISTEN")

    def test_listen_udp(self):
        line = "dhcpd    5678 root    6u  IPv4 0x...      0t0     UDP *:67"
        result = _parse_lsof_line(line)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["port"], 67)
        self.assertEqual(result["proto"], "UDP")

    def test_established_tcp(self):
        line = "Google  91011 legionsmacbook   42u  IPv4 0x...      0t0     TCP 192.168.1.5:54321->142.250.80.4:443 (ESTABLISHED)"
        result = _parse_lsof_line(line)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["port"], 443)
        self.assertEqual(result["proto"], "TCP")
        self.assertEqual(result["state"], "ESTABLISHED")

    def test_localhost_port(self):
        line = "postgres 89012 postgres   7u  IPv4 0x...      0t0     TCP 127.0.0.1:5432 (LISTEN)"
        result = _parse_lsof_line(line)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["port"], 5432)
        self.assertEqual(result["proto"], "TCP")
        self.assertEqual(result["state"], "LISTEN")

    def test_garbage_line(self):
        result = _parse_lsof_line("not enough fields")
        self.assertIsNone(result)

    def test_no_port(self):
        line = "foo     123 user   7u  IPv4 0x...    0t0    TCP *:* (LISTEN)"
        result = _parse_lsof_line(line)
        self.assertIsNone(result)


class TestFilterRecords(unittest.TestCase):
    """Test _filter_records."""

    def setUp(self):
        self.records = [
            {"port": 80, "proto": "TCP", "pid": 1, "process": "nginx", "state": "LISTEN", "user": "root", "name": "*:80 (LISTEN)"},
            {"port": 443, "proto": "TCP", "pid": 1, "process": "nginx", "state": "LISTEN", "user": "root", "name": "*:443 (LISTEN)"},
            {"port": 53, "proto": "UDP", "pid": 99, "process": "named", "state": "LISTEN", "user": "root", "name": "*:53"},
            {"port": 3000, "proto": "TCP", "pid": 500, "process": "node", "state": "LISTEN", "user": "user", "name": "*:3000 (LISTEN)"},
        ]

    def test_filter_by_port(self):
        result = _filter_records(self.records, port=80)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["port"], 80)

    def test_filter_by_port_not_found(self):
        result = _filter_records(self.records, port=9999)
        self.assertEqual(len(result), 0)

    def test_filter_tcp_only(self):
        result = _filter_records(self.records, proto_filter="TCP")
        self.assertEqual(len(result), 3)
        for r in result:
            self.assertEqual(r["proto"], "TCP")

    def test_filter_udp_only(self):
        result = _filter_records(self.records, proto_filter="UDP")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["port"], 53)

    def test_filter_all(self):
        result = _filter_records(self.records, proto_filter="all")
        self.assertEqual(len(result), 4)

    def test_no_filters(self):
        result = _filter_records(self.records)
        self.assertEqual(len(result), 4)


class TestFormatText(unittest.TestCase):
    """Test _format_text."""

    def test_empty(self):
        result = _format_text([])
        self.assertIn("No listening ports found", result)

    def test_single_record(self):
        records = [{"port": 80, "proto": "TCP", "pid": 123, "process": "nginx", "state": "LISTEN"}]
        result = _format_text(records)
        self.assertIn("80", result)
        self.assertIn("TCP", result)
        self.assertIn("123", result)
        self.assertIn("nginx", result)
        self.assertIn("LISTEN", result)

    def test_multiple_records(self):
        records = [
            {"port": 80, "proto": "TCP", "pid": 1, "process": "nginx", "state": "LISTEN"},
            {"port": 3000, "proto": "TCP", "pid": 500, "process": "node", "state": "LISTEN"},
        ]
        result = _format_text(records)
        lines = result.split("\n")
        # Header + separator + 2 data rows = at least 4 lines
        self.assertGreaterEqual(len(lines), 4)


class TestOutput(unittest.TestCase):
    """Test _output function."""

    def setUp(self):
        self.records = [{"port": 80, "proto": "TCP", "pid": 1, "process": "nginx", "state": "LISTEN"}]

    def test_text_output(self):
        buf = StringIO()
        with patch("sys.stdout", buf):
            _output(self.records, "text")
        output = buf.getvalue()
        self.assertIn("80", output)

    def test_json_output(self):
        buf = StringIO()
        with patch("sys.stdout", buf):
            _output(self.records, "json")
        output = buf.getvalue()
        parsed = json.loads(output)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["port"], 80)


class TestKnownServices(unittest.TestCase):
    """Test the KNOWN_SERVICES map."""

    def test_common_ports(self):
        self.assertEqual(KNOWN_SERVICES[22], "SSH")
        self.assertEqual(KNOWN_SERVICES[80], "HTTP")
        self.assertEqual(KNOWN_SERVICES[443], "HTTPS")
        self.assertEqual(KNOWN_SERVICES[5432], "PostgreSQL")
        self.assertEqual(KNOWN_SERVICES[6379], "Redis")
        self.assertEqual(KNOWN_SERVICES[3000], "Node / Dev")


class TestParser(unittest.TestCase):
    """Test argument parser."""

    def test_scan_default(self):
        parser = build_parser()
        args = parser.parse_args(["scan"])
        self.assertEqual(args.command, "scan")
        self.assertFalse(args.tcp)
        self.assertFalse(args.udp)
        self.assertFalse(args.all)
        self.assertEqual(args.format, "text")

    def test_scan_with_port(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--port", "8080"])
        self.assertEqual(args.port, 8080)

    def test_scan_tcp(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--tcp"])
        self.assertTrue(args.tcp)

    def test_scan_json(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--format", "json"])
        self.assertEqual(args.format, "json")

    def test_lookup(self):
        parser = build_parser()
        args = parser.parse_args(["lookup", "5432"])
        self.assertEqual(args.command, "lookup")
        self.assertEqual(args.port, 5432)

    def test_watch_default(self):
        parser = build_parser()
        args = parser.parse_args(["watch"])
        self.assertEqual(args.command, "watch")
        self.assertEqual(args.interval, 3.0)

    def test_watch_interval(self):
        parser = build_parser()
        args = parser.parse_args(["watch", "--interval", "5"])
        self.assertEqual(args.interval, 5.0)


if __name__ == "__main__":
    unittest.main()

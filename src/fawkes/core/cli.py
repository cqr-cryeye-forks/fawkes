# src/core/cli.py
"""
Command‑line interface for Fawkes.
Now supports either a Google Dork **or** a single URL via --url.
"""
from __future__ import annotations

import argparse
from argparse import Namespace


class Cli:
    @staticmethod
    def parse_args() -> Namespace:
        parser = argparse.ArgumentParser(
            prog="fawkes",
            description="Find SQLi‑vulnerable targets via Google Dorks or test a single URL",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        )

        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument(
            "-q",
            "--query",
            type=str,
            help="Google Dork to search for",
        )
        group.add_argument(
            "-u",
            "--url",
            type=str,
            help="Single target URL to test (skips Google search)",
        )

        parser.add_argument(
            "-o",
            "--output",
            type=str,
            required=True,
            help="Path to output JSON file",
        )
        parser.add_argument("-r", "--results", type=int, default=100, help="Number of Google results")
        parser.add_argument("-s", "--start-page", type=int, default=0, help="Start page offset")
        parser.add_argument("-t", "--timeout", type=float, default=1.0, help="HTTP timeout (s)")
        parser.add_argument("-th", "--threads", type=int, default=1, help="Concurrent threads")
        parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

        return parser.parse_args()

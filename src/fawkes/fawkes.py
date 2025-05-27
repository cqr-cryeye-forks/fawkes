# src/__main__.py
# !/usr/bin/env python3
"""
Fawkes: Entry point for the SQLi vulnerability scanner.
Compatible with Python 3.13.1+
"""
import logging

from fawkes.core.cli import Cli
from fawkes.core.scan import Scan


def main() -> None:
    """Parse arguments and run the scan."""
    args = Cli.parse_args()

    # Configure root logger
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    logging.info("Starting Fawkes scan...")

    scanner = Scan(args)
    scanner.scan()

# src/vulls/sqli.py
"""
Sqli: SQL injection tester module.
Compatible with Python 3.13.1+.
"""
import logging
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)


class Sqli:
    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose
        self.data: list[dict[str, str]] = []

    def _generate_payload_urls(self, url: str) -> list[str]:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        queries = parsed.query.split("&") if parsed.query else []
        payload_urls: list[str] = []

        for query in queries:
            payload_url = f"{base}?{query}'"
            payload_urls.append(payload_url)
        return payload_urls

    def _has_error(self, text: str) -> bool:
        errors = [
            "mysql_fetch_array()", "You have an error in your SQL syntax",
            "MySQL Query fail.", "PostgreSQL ERROR", "Access Database Engine",
            "Microsoft Access Driver"
        ]
        return any(err in text for err in errors)

    def check_vull(self, url: str) -> None:
        for target in self._generate_payload_urls(url):
            try:
                response = requests.get(url=target, timeout=10)
            except requests.RequestException as e:
                logger.warning("Connection issue for %s: %s", target, e)
                continue

            if self._has_error(response.text):
                logger.info("SQLi vulnerability found: %s", target)
                self.data.append({"success": target})
            elif self.verbose:
                logger.debug("No SQL error at %s", target)
                self.data.append({"error": target})

    def data_return(self) -> list[dict[str, str]]:
        return self.data

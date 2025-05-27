# src/core/filter.py
"""
Link filter: parses and filters URLs from HTTP responses.
Compatible with Python 3.13.1+.
"""
import logging
from typing import List, Any
from urllib.parse import urlparse

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class Filter:
    def __init__(self, response: Any) -> None:
        self.response = response
        self._links: List[str] = []

    def __len__(self) -> int:
        return len(self._links)

    def __getitem__(self, idx: int) -> str:
        return self._links[idx]

    def _is_valid_url(self, url: str) -> bool:
        parsed = urlparse(url)
        return bool(parsed.scheme and parsed.netloc)

    def _load_blacklist(self) -> List[str]:
        try:
            with open('blacklist/links.txt', 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except OSError as e:
            logger.error("Failed to load blacklist: %s", e)
            return []

    def filter_links(self) -> List[str]:
        soup = BeautifulSoup(self.response.text, "lxml")
        anchors = soup.find_all("a", href=True)
        for tag in anchors:
            href = tag['href'].replace('/url?q=', '')
            if self._is_valid_url(href):
                self._links.append(href)
        logger.info("Filtered %d raw links", len(self._links))
        return self._links

    def remove_links(self, links: List[str]) -> List[str]:
        blacklist = self._load_blacklist()
        filtered = [ln for ln in links if not any(blk in ln for blk in blacklist)]
        logger.info("Removed %d blacklisted links", len(links) - len(filtered))
        return filtered

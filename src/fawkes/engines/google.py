# src/fawkes/engines/google.py
"""
GoogleSearch: handles Google-Dork querying.
Compatible with Python 3.13.1+
"""
from __future__ import annotations

import random
import time
import logging
from typing import Any, Dict, List, Tuple

import requests

from fawkes.core.errors import GoogleError

logger = logging.getLogger(__name__)


class GoogleSearch:
    """
    Выполняет поисковые запросы в Google, перемешивая User-Agent'ы и зеркала,
    а также поддерживает прокси и задержку между запросами.
    """

    def __init__(
        self,
        params: Dict[str, Any],
        timeout: float = 1.0,
        delay_range: Tuple[float, float] = (1.0, 3.0),
        ignore_block: bool = True,
        proxies: Dict[str, str] | None = None,
    ) -> None:
        self.params = params
        self.timeout = timeout
        self.delay_range = delay_range
        self.ignore_block = ignore_block
        self.proxies = proxies or {}
        self._block_phrase = "Our systems have detected unusual traffic"

    # ---------- helpers --------------------------------------------------

    @staticmethod
    def _load_list(path: str) -> List[str]:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return [line.strip() for line in fh if line.strip()]
        except OSError as exc:
            logger.error("Failed to load list from %s: %s", path, exc)
            raise GoogleError(f"Unable to load file {path}") from exc

    def _user_agents(self) -> List[str]:
        return self._load_list("commonlist/user_agents.txt")

    def _google_urls(self) -> List[str]:
        return self._load_list("commonlist/google_url.txt")

    # ---------- main -----------------------------------------------------

    def request(self) -> List[requests.Response]:
        uagents = self._user_agents()
        gurls = self._google_urls()
        random.shuffle(uagents)
        random.shuffle(gurls)

        responses: List[requests.Response] = []
        start_time = time.time()

        for idx, gurl in enumerate(gurls, start=1):
            for ua in uagents:
                # Случайная задержка — помогает избежать блокировки.
                sleep_for = random.uniform(*self.delay_range)
                time.sleep(sleep_for)

                try:
                    resp = requests.get(
                        gurl,
                        params=self.params,
                        timeout=self.timeout,
                        headers={"User-Agent": ua},
                        proxies=self.proxies,
                    )
                except requests.RequestException as err:
                    logger.warning("Request failed for %s with UA %s: %s", gurl, ua, err)
                    continue

                # Проверяем страницу-заглушку Google
                if self._block_phrase in resp.text:
                    logger.error("Google detected malicious traffic for %s", gurl)
                    if self.ignore_block:
                        # Просто пропускаем этот ответ
                        continue
                    raise GoogleError("Google detected malicious traffic")

                responses.append(resp)

            logger.debug(
                "Processed %d Google mirrors in %.1f s",
                idx,
                time.time() - start_time,
            )

            # Отсек: не крутимся больше часа
            if time.time() - start_time >= 3600:
                logger.info("Stopping after reaching 1-hour limit.")
                break

        return responses

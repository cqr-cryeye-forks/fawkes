# src/core/scan.py
"""
Core scanning functionality: fetches search results, filters links, and tests for SQLi.
"""
import json
import logging
import pathlib
from argparse import Namespace
from multiprocessing.dummy import Pool as ThreadPool
from typing import Any

from fawkes.core.filter import Filter
from fawkes.engines.google import GoogleSearch
from fawkes.vulls.sqli import Sqli

logger = logging.getLogger(__name__)


class Scan:
    def __init__(self, args: Namespace) -> None:
        self.args = args

    def _fetch_responses(self) -> list[Any]:
        params = {
            'query': self.args.query,
            'start': self.args.start_page,
            'num': self.args.results
        }
        logger.debug(f"Search params: {params}")
        searcher = GoogleSearch(params=params, timeout=self.args.timeout)
        return searcher.request()

    def scan(self) -> None:
        logger.info("Fetching search results...")
        responses = self._fetch_responses()
        all_results: list[dict[str, Any]] = []

        for response in responses:
            links = Filter(response).filter_links()
            valid_links = Filter(response).remove_links(links)

            if not valid_links:
                continue

            logger.info(f"Testing {len(valid_links)} targets for SQLi...")
            sqli_tester = Sqli(verbose=self.args.verbose)
            with ThreadPool(self.args.threads) as pool:
                pool.map(sqli_tester.check_vull, valid_links)

            result = {'vulnerabilities': sqli_tester.data_return()}
            all_results.append(result)

        output_path = pathlib.Path(self.args.output)
        if not all_results:
            logger.warning("No vulnerabilities found.")
            summary = {'Empty': 'Nothing found by Fawkes'}
            output_data = summary
        else:
            output_data = all_results

        logger.info(f"Saving results to {output_path}")
        output_path.write_text(json.dumps(output_data, indent=2), encoding='utf-8')
        logger.info("Scan complete.")

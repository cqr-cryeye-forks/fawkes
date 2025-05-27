# src/core/scan.py
"""
Core scanning functionality: fetches search results, filters links, and tests for SQLi.
Supports both Google Dork search and single URL scanning.
"""
import json
import logging
import pathlib
from argparse import Namespace
from multiprocessing.dummy import Pool as ThreadPool
from typing import Any, List, Dict

from fawkes.core.filter import Filter
from fawkes.engines.google import GoogleSearch
from fawkes.vulls.sqli import Sqli

logger = logging.getLogger(__name__)


class Scan:
    def __init__(self, args: Namespace) -> None:
        self.args = args

    def _fetch_responses(self) -> List[Any]:
        params = {
            'query': self.args.query,
            'start': self.args.start_page,
            'num': self.args.results
        }
        logger.debug("Search params: %s", params)
        searcher = GoogleSearch(params=params, timeout=self.args.timeout)
        return searcher.request()

    def scan(self) -> None:
        """
        Execute scanning: if URL provided, test it directly; otherwise perform Google search.
        """
        all_results: List[Dict[str, Any]] = []

        if self.args.url:
            # Direct URL mode
            logger.info("Testing single URL for SQLi: %s", self.args.url)
            sqli = Sqli(verbose=self.args.verbose)
            sqli.check_vull(self.args.url)
            all_results.append({'vulnerabilities': sqli.data_return()})
        else:
            # Google Dork mode
            logger.info("Fetching search results...")
            responses = self._fetch_responses()
            for response in responses:
                links = Filter(response).filter_links()
                valid_links = Filter(response).remove_links(links)

                if not valid_links:
                    continue

                logger.info("Testing %d targets for SQLi...", len(valid_links))
                sqli = Sqli(verbose=self.args.verbose)
                with ThreadPool(self.args.threads) as pool:
                    pool.map(sqli.check_vull, valid_links)
                all_results.append({'vulnerabilities': sqli.data_return()})

        # Save results to JSON
        output_path = pathlib.Path(self.args.output)
        if not all_results or all_results == [{'vulnerabilities': []}]:
            logger.warning("No vulnerabilities found.")
            output_data = {'Empty': 'Nothing found by Fawkes'}
        else:
            output_data = all_results

        logger.info("Saving results to %s", output_path)
        output_path.write_text(json.dumps(output_data, indent=2), encoding='utf-8')
        logger.info("Scan complete.")

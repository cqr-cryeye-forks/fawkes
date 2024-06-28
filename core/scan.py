import json
import pathlib
import time
from typing import Final

from core.filter import Filter
from engines.google import GoogleSearch
from vulls.sqli import Sqli

from colorama import init
from termcolor import colored
from multiprocessing.dummy import Pool as ThreadPool

# use Colorama to make Termcolor work on Windows too
init(autoreset=True)


class Scan(Filter):
    def __init__(self, args):
        self.args = args

    def _get_response(self):
        self.args.query = self.args.query
        # .replace("//", "/")
        params = {
            'query': self.args.query,
            'start': self.args.start_page,
            'num': self.args.results
        }
        print(params)
        req = GoogleSearch(params=params, timeout=self.args.timeout)
        list_response = req.request()
        print(list_response)
        return list_response

    def scan(self):
        responses = self._get_response()
        all_result = []
        for response in responses:
            links = Filter(response).filter_links()
            links_parsed = self.remove_links(links)
            # links_parsed = [self.args.query]
            if len(links_parsed) > 0:
                print(f"Number of targets: {len(links_parsed)}")
                print("-" * 111)

            sqli = Sqli(self.args.verbose)
            data = sqli.data_return()
            pool = ThreadPool(self.args.threads)
            pool_exec = pool.map(sqli.check_vull, links_parsed)
            pool.close()
            pool.join()
            result = {"data": data}
            all_result.append(result)

        MAIN_DIR: Final[pathlib.Path] = pathlib.Path(__file__).parent.parent
        OUTPUT_JSON: Final[pathlib.Path] = MAIN_DIR / self.args.output
        print("-" * 111, "\n", "SAVE RESULT IN:", OUTPUT_JSON)
        if all_result == []:
            all_result = {
                "Empty": "Nothing found by Fawkes"
                }
        with open(OUTPUT_JSON, "w") as jf:
            json.dump(all_result, jf, indent=2)

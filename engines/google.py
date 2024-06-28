import time

import requests
import random
import sys

from core.errors import GoogleError
from colorama import init

# use Colorama to make Termcolor work on Windows too
init(autoreset=True)


class GoogleSearch:
    def __init__(self, params={}, timeout=1):
        self.params = params
        self.timeout = timeout
        self._malicious_traffic = "Our systems have detected unusual traffic"

    def _load_user_random_agents(self):
        with open("commonlist/user_agents.txt", "r") as user_agent:
            user_agents = user_agent.read().splitlines()
            # user_agent = random.choice(list(user_agents))

        return user_agents

    def _load_random_google_url(self):
        with open("commonlist/google_url.txt", "r") as google_url:
            google_urls = google_url.read().splitlines()
            # google_url = random.choice(list(google_urls))

        return google_urls

    def request(self):
        google_urls = self._load_random_google_url()
        user_agents = self._load_user_random_agents()
        random.shuffle(google_urls)
        random.shuffle(user_agents)
        # print(f"Random google URL: {google_url}")
        # print(f"Random User-Agent: {user_agent}")
        list_requests = []
        list_error = []
        t_start = time.time()
        for i, google_url in enumerate(google_urls):
            for user_agent in user_agents:
                try:
                    req = requests.get(
                        url=google_url,
                        params=self.params,
                        timeout=self.timeout,
                        headers={
                            "User-Agent": user_agent
                        })
                except requests.exceptions.RequestException as e:
                    print(f"Requests error: {e}")
                    exit(1)

                if self._malicious_traffic in req.text:
                    data_Error = {"GoogleError": "Google detected malicious traffic"}
                    list_error.append(data_Error)
                list_requests.append(req)
            print(i, time.time() - t_start)
            if time.time() - t_start >= 3600:   # 1/3 of all google_urls
                print("BREAK of main cycle")
                break
        return list_requests


#!/usr/bin python3
# -*- coding: utf-8 -*-

from modules.style import *
from modules.functions import *
from modules.functions import DeleteDuplicate
from modules.functions import write_file
import json
import requests
import time
__Name__ = "TheNetRecon"
__Description__ = "Network Recon Tool."
__author__ = "Md. Nur Habib"
__Version__ = "1.0"

# Import Modules
from modules import useragents


class Threatcrowd:

    def __init__(self, target, output):

        self.target = target
        self.output = output
        self.module_name = "Threat Crowd"
        self.engine = "threatcrowd"
        self.response = self.engine_url()

        if self.response != 1:
            print(
                f"\n{bold}{blue}ThreatCrowd: Enumerating subdomains now for {target} {reset}\n")

            self.enumerate(self.response, output, target)
        else:
            pass

    def engine_url(self):
        try:
            url = f'https://threatcrowd.org/searchApi/v2/domain/report/?domain={self.target}'
            response = requests.get(url, headers=useragents.useragent())
            return response
        except requests.ConnectionError:
            print(
                f"{bold}{red}[Threat Crowd] Warning! Unable to get subdomains.\n")
            response = 1
            return response

    def enumerate(self, response, output, target):
        subdomains = set()
        subdomainscount = 0
        start_time = time.time()

        try:

            subdomains = response.json()["subdomains"][subdomainscount]
        except KeyError:
            print(
                f"{bold}{red}No data found for {self.target} using Threat Crowd.{reset}")
            exit(1)

        try:
            while subdomainscount < 500:
                subdomains = response.json()["subdomains"][subdomainscount]
                subdomainscount = subdomainscount + 1
                print(f"[*] {subdomains}")
                if self.output is not None:
                    write_file(subdomains, self.engine +
                               '_' + self.output, target)
            if self.output:
                print(f"\nSaving result... {self.engine + '_' + self.output}")
        except IndexError:
            pass

        if not subdomains:
            print(
                f"{bold}{red}[x] No data found for {self.target} using Threat Crowd.\n{reset}")
        else:
            print(f"\n[**]Threat Crowd: {subdomainscount} subdomains have been found in %s seconds" % (
                time.time() - start_time) + "\n")
            if self.output is not None:
                DeleteDuplicate(self.engine + '_' + self.output, target)

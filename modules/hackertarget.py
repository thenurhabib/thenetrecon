
#!/usr/bin python3
# -*- coding: utf-8 -*-

__Name__ = "TheNetRecon"
__Description__ = "Network Recon Tool."
__author__      = "Md. Nur Habib"
__Version__ = "1.0"

import time
import requests

from modules import useragents  

from modules.functions import write_file
from modules.functions import DeleteDuplicate
from modules.functions import *
from modules.style import *


class Hackertarget:

    def __init__(self, target, output):

        self.target = target
        self.output = output
        self.module_name = "HackerTarget"
        self.engine = "hackertarget"
        self.response = self.engine_url()

        if self.response != 1:
            print(f"\nf{bold}{blue}HackerTarget: Enumerating subdomains now for {reset} {target} \n")
            
            self.enumerate(self.response, output, target)
        else:
            pass

    def engine_url(self):
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.target}"
            response = requests.get(url, headers=useragents.useragent())
            return response
        except requests.ConnectionError:
            print(f"{bold}{red}[HackerTarget] Warning! Unable to get subdomains. Try again!\n{reset}")
            response = 1
            return response


    def enumerate(self, response, output, target):
        subdomains = []
        subdomainscount = 0
        sub = []
        start_time = time.time()
        
        try:
            while subdomainscount < 10000:
                
                remove_ip = response.text.replace(",", " ")
                subdomains = remove_ip.split()
                
                subdomainscount = subdomainscount + 2
                print(f"[*] {subdomains[subdomainscount]}")
                
                if self.output is not None and int((subdomainscount / 2) - 1) != 0:
                    write_file(subdomains[subdomainscount],
                               self.engine + '_' + self.output, target)
                else:
                    pass
        except IndexError:
            pass
        
        if self.output and not subdomains:
            print(f"\nSaving result... {self.engine + '_' + self.output}")
        if not subdomains:
            print(
                f"{bold}{red}No data found for {self.target} using  HackerTarget.{reset}\n")
        else:
            print(f"\n[**]HackerTarget: {int((subdomainscount / 2) - 1)} subdomains have been found in %s seconds" % (
                time.time() - start_time) + "\n")
            if self.output is not None and int((subdomainscount / 2) - 1) != 0:
                DeleteDuplicate(self.engine + '_' + self.output, target)
            else:
                pass

#!/usr/bin python3
# -*- coding: utf-8 -*-

__Name__ = "TheNetRecon"
__Description__ = "Network Recon Tool."
__author__      = "Md. Nur Habib"
__Version__ = "1.0"

# Import Modules
import time
import requests
import json

from modules import useragents  

from modules.functions import write_file
from modules.functions import DeleteDuplicate
from modules.functions import *
from modules.style import *


class CRT:

    def __init__(self, target, output):

        self.target = target
        self.output = output
        self.module_name = "SSL Certificates"
        self.engine = "crt"
        self.response = self.engine_url()  

        if self.response != 1:
            print(f"{bold}{blue}\nSSL Certificates: Enumerating subdomains now for {target} {reset}\n")
            
            self.enumerate(self.response, output, target)
        else:
            pass
        if self.output is not None and self.subdomainscount != 0:
            DeleteDuplicate(self.engine + '_' + self.output, target)
        else:
            pass


    def engine_url(self):
        try:
            url = f"https://crt.sh/?q={self.target}&output=json"
            response = requests.get(url, headers=useragents.useragent())
            return response
        except requests.ConnectionError:
            print(f"{bold}{red}[SSL] Warning! Unable to get subdomains.\n{reset}")
            response = 1
            return response


    def enumerate(self, response, output, target):
        subdomains = set()
        self.subdomainscount = 0
        start_time = time.time()
        
        
        try:
            subdomains = response.json()
        except ValueError:  
            print(f"{bold}{reset}Decoding JSON has failed.{reset}\n")
            exit(1)

        
        try:
            while self.subdomainscount < 10000:
                subdomains = response.json(
                )[self.subdomainscount]["name_value"]

                self.subdomainscount = self.subdomainscount + 1
                if "@" in subdomains:  
                    pass
                else:
                    print(f"[*] {subdomains}")
                    if self.output is not None:
                        write_file(subdomains, self.engine +
                                   '_' + self.output, target)
            if self.output:
                print(f"\nSaving result... {self.engine + '_'+ self.output}")
        except IndexError:
            pass
        
        if not subdomains:
            print(
                f"[x] Oops! No data found for {self.target} using  SSL Certificates.\n")
            exit(2)
        else:
            print(f"\n[**]SSL Certificates: {self.subdomainscount} subdomains have been found in %s seconds" % (
                time.time() - start_time) + "\n")

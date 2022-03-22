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



class Certspotter:

    def __init__(self, target, output):

        self.target = target
        self.output = output
        self.module_name = "CertSpotter"
        self.engine = "certspotter"
        self.response = self.engineUrlFunction()

        if self.response != 1:
            print(
                f"\nCertSpotter: Enumerating subdomains now for {target} \n")
            
            self.enumerateFunction(self.response, output, target)
        else:
            pass
        
            


    def engineUrlFunction(self):
        try:
            url = f'https://api.certspotter.com/v1/issuances?domain={self.target}&include_subdomains=true&expand=dns_names'
            response = requests.get(url, headers=useragents.useragent())
        except (requests.ConnectionError, requests.Timeout) as exception:
            print(
                f"[CertSpotter] Warning! Unable to get subdomains... Try again!\n")
            response = 1
        return response



    def parseUrlFunction(url):
        try:
            host = urllib3.util.url.parseUrlFunction(url).host
        except Exception as e:
            print('[*] Invalid domain, try again...')
            sys.exit(1)
        return host


    def enumerateFunction(self, response, output, target):
        subdomains = []
        subdomainscount = 0
        start_time = time.time()
        
        try:
            while subdomainscount < 100:
                subdomains = response.json()[subdomainscount]["dns_names"][0]
                subdomainscount = subdomainscount + 1
                print(f"[*] {subdomains}")
                if self.output is not None:
                    write_file(subdomains, self.engine +
                               '_' + self.output, target)
            if self.output:
                print(f"\nSaving result... {self.engine + '_' + self.output}")
        except:
            pass
        
        if not subdomains:
            print(f"[x] No data found for {self.target} using CertSpotter.")
        else:
            print(f"\n[**]CertSpotter: {subdomainscount} subdomains have been found in %s seconds" % (
                time.time() - start_time))
            if self.output is not None:
                DeleteDuplicate(self.engine + '_' + self.output, target)

#!/usr/bin python3
# -*- coding: utf-8 -*-

__Name__ = "TheNetRecon"
__Description__ = "Network Recon Tool."
__author__ = "Md. Nur Habib"
__Version__ = "1.0"

# Import Module
import argparse
from modules.style import *
from modules import td
from modules import hackertarget
from modules import crt
from modules import certspotter
from modules.dns import whoisLockupFunction
from modules.dns import DNSRecordTypesFunction
from modules.bruteforce import TugaBruteForce
from modules.functions import mappingDomainFunction
from modules.functions import *
import requests
import urllib3
import time
import sys



def bannerFunction():
    print(f"""{yellow}{bold}
          
  ________         _   __     __  ____                
 /_  __/ /_  ___  / | / /__  / /_/ __ \___  _________  ____ 
  / / / __ \/ _ \/  |/ / _ \/ __/ /_/ / _ \/ ___/ __ \/ __ \\
 / / / / / /  __/ /|  /  __/ /_/ _, _/  __/ /__/ /_/ / / / /
/_/ /_/ /_/\___/_/ |_/\___/\__/_/ |_|\___/\___/\____/_/ /_/{cyan} {__Version__} {red}
                        
                                @thenurhabib {reset}
                                
""")


def parse_args():

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser._optionals.title = "OPTIONS"
    parser.add_argument(
        '-d', '--domain', help="[required] Domain name to enumerate it's subdomains", required=True)
    parser.add_argument('-o', '--output', metavar='',
                        help='Save results in txt file.')
    parser.add_argument('-i', '--ignore', dest='i', default=False,
                        action='store_true', help='Ignore domains pointed to private IPs')
    parser.add_argument('-f', '--file', metavar='', dest='file', default='first_names.txt',
                        help='A file contains new line delimited subdomains.')
    parser.add_argument('-s', '--save',
                        help='Save subdomains image map', action='store_true')
    parser.add_argument('-b', '--bruteforce',
                        help='Enable the bruteforce scan', action='store_true')
    parser.add_argument('-t', '--threads', metavar='',
                        help="Number of threads. [Default 200]", default=200, type=int)
    parser.add_argument(
        '--enum', nargs='*', help='<optional> Perform enumerations and network mapping')
    parser.add_argument('--full', dest='full_scan', default=False, action='store_true',
                        help='Full scan, NAMES FILE first_names_full.txt will be used to brute')
    return parser.parse_args()


def parserUrlFunction(url):
    try:
        host = urllib3.util.url.parse_url(url).host
        response = requests.get('http://' + host)
        if (response.status_code == 200):
            print(f'{bold}{green}Target Online = {blue}True{reset}')
        else:
            print(f'{bold}{red}Invalid domain.{reset}')
    except Exception as e:
        print('{bold}{red}Network unstable.{reset}')

    return host


def internetCheck():
    url = "https://www.google.com"

    testTimeOut = 1
    try:
        request = requests.get(url, timeout=testTimeOut)
        print(f"{bold}{green}\nConnection established.\n{reset}")
        time.sleep(0.5)
    except (requests.ConnectionError, requests.Timeout) as exception:
        print(f"{bold}{red}No internet connection.\n{reset}")
        exit(1)


def queriesFunction(target):
    print(f"\n{bold}{blue}Enumerating subdomains for {target} \n=========================================={reset}")
    time.sleep(1)
    print(f"{bold}{blue}[-] Searching {target} in CertsPotter{reset}")
    print(f"{bold}{blue}[-] Searching {target} in SSL Certificates{reset}")
    print(f"{bold}{blue}[-] Searching {target} in HackerTarget{reset}")
    print(f"{bold}{blue}[-] Searching {target} in ThreatCrowd{reset}\n")
    time.sleep(0.5)
    print(f"{bold}{orange}Wait for results.\n{reset}")
    return (0)


def main(target, output, save, enum, threads, bruteforce, args):

    if bruteforce:
        subdomainTesting = TugaBruteForce(options=args)
        subdomainTesting.run()
        subdomainTesting.outfile.flush()
        subdomainTesting.outfile.close()
        sys.exit()
    try:
        supportedENginens = {'certspotter': certspotter.Certspotter,
                             'ssl': crt.CRT,
                             'hackertarget': hackertarget.Hackertarget,
                             'threatcrowd': td.Threatcrowd}
        chosenEnums = []

        if enum is None:
            queriesFunction(target)
            chosenEnums = [certspotter.Certspotter, crt.CRT,
                           hackertarget.Hackertarget, td.Threatcrowd]

            enums = [indicate(target, output) for indicate in chosenEnums]
        else:
            for engine in enum:
                if engine.lower() in supportedENginens:
                    chosenEnums.append(supportedENginens[engine.lower()])
                    print("\nWait for results...!\n")

                    enums = [indicate(target, output)
                             for indicate in chosenEnums]

        if save is not False:
            mappingDomainFunction(target)
    except KeyboardInterrupt:
        print(f"{bold}{red}\ninterrupted.\n{reset}")
        sys.exit()


def mainMenuFunction():
    bannerFunction()
    args = parse_args()
    target = parserUrlFunction(args.domain)
    enum = args.enum
    bruteforce = args.bruteforce
    threads = args.threads
    output = args.output
    save = args.save
    internetCheck()
    DNSRecordTypesFunction(target)
    whoisLockupFunction(target)
    main(target, output, save, enum, threads, bruteforce, args)


if __name__ == "__main__":
    mainMenuFunction()

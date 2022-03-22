#!/usr/bin python3
# -*- coding: utf-8 -*-

__Name__ = "TheNetRecon"
__Description__ = "Network Recon Tool."
__author__      = "Md. Nur Habib"
__Version__ = "1.0"

import dns.resolver
import whois
from modules.style import *
from modules.functions import *


def DNSRecordTypesFunction(target):
    print(f"{blue}{bold}\nDNS Record Types.{reset} {blue}{bold}\n================={reset}\n")


    recordTypesVariable = ['A', 'AAAA', 'AFSDB', 'NS', 'CNAME', 'MX', 'PTR', 'SOA', 'CERT',
                    'HINFO', 'MINFO', 'TLSA', 'SPF', 'KEY', 'NXT', 'CAA', 'TXT', 'MD',
                    'NULL', 'DNAME', 'URI', 'DLV', 'APL', 'CSYNC', 'DHCID', 'LOC']

    for record in recordTypesVariable:
        try:
            answer = dns.resolver.resolve(target, record)
            print(f'\nRecords: {record}')
            print('-' * 30)
            for rdata in answer:
                print(rdata.to_text())
        except dns.resolver.NoAnswer:
            pass
        except dns.exception.Timeout:
            pass
        except dns.resolver.NXDOMAIN:
            print(f'{target} does not exist.')
            
            quit()
        except KeyboardInterrupt:
            print('Quitting.')
            quit()


def whoisLockupFunction(target):
    try:
        dict = []
        domain = whois.query(target)
        data = domain.__dict__
        dict.append(data)

        print("Domain expiration: ", domain.expiration_date)
        for dict_line in dict:
            for k, v in dict_line.items():
                print(": ")
    except Exception as e:
        pass


@staticmethod
def isInternet(ip):
    ret = ip.split('.')
    if not len(ret) == 4:
        return True
    if ret[0] == '10':
        return True
    if ret[0] == '172' and 16 <= int(ret[1]) <= 32:
        return True
    if ret[0] == '192' and ret[1] == '168':
        return True
    return False

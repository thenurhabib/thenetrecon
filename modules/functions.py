#!/usr/bin python3
# -*- coding: utf-8 -*-

__Name__ = "TheNetRecon"
__Description__ = "Network Recon Tool."
__author__      = "Md. Nur Habib"
__Version__ = "1.0"

# Import Modules
import sys
import urllib.request
import webbrowser
import urllib.error
import urllib3
import os
from pathlib import Path
from modules.style import *

def write_file(subdomains, outputFile, target):
    if not os.path.exists(f"results/{target}"):
        os.mkdir(f"results/{target}")
    else:
        pass
    try:
        with open(f"results/{target}/tmp.txt", 'a') as tmp:
            tmp.write(subdomains + '\n')
        tmp.close()
    except:
        pass


def DeleteDuplicate(outputFile, target):
    content = open(f"results/{target}/tmp.txt", 'r').readlines()
    contentSet = set(content)
    cleanData = open(f"results/{target}/{outputFile}, 'w'")
    for line in contentSet:
        cleanData.write(line)
    try:
        os.remove("results/{target}/tmp.txt")
    except OSError:
        pass


def mappingDomainFunction(target):
    if not os.path.exists(f"results/{target}"):
        os.mkdir(f"results/{target}")
    else:
        pass
    try:
        try:
            urllib.request.urlretrieve(f"https://dnsdumpster.com/static/map/{target}" + ".png",
                                       f"results/{target}/{target}.png")
        except urllib.error.URLError as e:
            print("", e.reason)
        my_file = Path(f"results/{target}/{target}.png")
        if my_file.is_file():
            webbrowser.open(f"results/{target}/{target}.png")
        else:
            print(f"\n{bold}{red}Oops! The map file was not generated. Try again.{reset}\n")
    except PermissionError:
        print(f"{bold}{red}[PERMISSION DENIED] Only root user can perform this privileges.{reset}")

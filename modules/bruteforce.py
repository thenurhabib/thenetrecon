#!/usr/bin python3
# -*- coding: utf-8 -*-

from modules.terminal import getTerminalSize
from modules.dns import isInternet
from modules.functions import *
from modules.style import *
import dns.resolver
import time
import threading
import sys
import re
import queue
import os
__Name__ = "TheNetRecon"
__Description__ = "Network Recon Tool."
__author__ = "Md. Nur Habib"
__Version__ = "1.0"

# Module


class TugaBruteForce:
    def __init__(self, options):

        self.target = options.domain
        self.options = options
        self.ignoreInternet = options.i
        self.subdomainWordlist = ""
        self.threadCount = self.scanCount = self.foundCount = 0
        self.lock = threading.Lock()

        self.consoleWidth = getTerminalSize()[0] - 2

        self.messageQueue = queue.Queue()
        self.stopScan = False

        threading.Thread(target=self.printMessageFunction).start()

        self.loadDNSServices()

        self.resolvers = [dns.resolver.Resolver(
            configure=False) for number in range(options.threads)]
        for number in self.resolvers:
            number.lifetime = number.timeout = 6.0

        self.loadSecoundSubNames()
        self.queue = queue.Queue()

        t = threading.Thread(target=self.loadFirstSubName)
        t.start()

        while not self.queue.qsize() > 0 and t.is_alive():
            time.sleep(0.1)

        if options.output:
            outfile = options.output
            if not os.path.exists("results/" + self.target):
                os.mkdir("results/" + self.target)
            outfile = 'results/' + self.target + "/" + outfile + '_tuga_bruteforce.txt' if not options.fullScan else 'results/' + \
                self.target + "/" + outfile + '_tuga_bruteforce_full.txt'
        else:
            outfile = 'results/' + "_tmp" + \
                '.txt' if not options.fullScan else 'results/' + "_tmp" + '.txt'
        self.outfile = open(outfile, 'w')

        self.ipDictonary = {}
        self.lastScanned = time.time()
        self.exResolver = dns.resolver.Resolver(configure=False)
        self.startTime = None

    def loadDNSServices(self):

        try:
            print(f'{bold}{blue}Initializing, validate DNS servers.{reset}')
            self.dnsServices = []
            with open('wordlist/dnsServices.txt') as f:
                for line in f:
                    server = line.strip()
                    if not server:
                        continue
                    while True:
                        if threading.activeCount() < 50:

                            t = threading.Thread(
                                target=self.testDNSServices, args=(server,))
                            t.start()
                            break
                        else:
                            time.sleep(0.1)

            while threading.activeCount() > 2:
                time.sleep(0.1)

            self.dnsCount = len(self.dnsServices)

            print('[+] Found %s available DNS Servers' % self.dnsCount)
            if self.dnsCount == 0:
                print(
                    f'{bold}{red}[ERROR] Oops! No DNS Servers available.{reset}')
                self.stopScan = True
                sys.exit(-1)
        except KeyboardInterrupt:
            print('Quitting.')
            quit()

    def testDNSServices(self, server):

        resolver = dns.resolver.Resolver(configure=False)
        resolver.lifetime = resolver.timeout = 10.0
        try:
            resolver.nameservers = [server]

            answers = resolver.query('s-coco-ns01.co-co.nl')
            if answers[0].address != '188.122.89.156':
                raise Exception('incorrect DNS response')
            try:

                resolver.query('test.bad.dns.skynet0x01.pt')
                with open('wordlist/bad_dnsServices.txt', 'a') as f:
                    f.write(server + '\n')

                self.messageQueue.put(
                    f'{bold}{red}[+] Bad DNS Server found %s{reset}' % server)
            except:

                self.dnsServices.append(server)
            self.messageQueue.put(f'{bold}{green}[+] Check DNS Server %s < OK >   Found {reset}%s' %
                                  (server.ljust(16), len(self.dnsServices)))
        except:
            self.messageQueue.put(f'{bold}{red}[+] DNS Server %s <Fail>   Found {reset} %s' %
                                  (server.ljust(16), len(self.dnsServices)))

    def loadFirstSubName(self):

        if self.options.fullScan and self.options.file == 'first_names.txt':
            _file = 'wordlist/first_names_full.txt'
            self.messageQueue.put(
                f'{bold}{blue}[+] Load the first list.{reset}' + _file)
        else:
            if os.path.exists(self.options.file):
                _file = self.options.file
                self.messageQueue.put(
                    f'{bold}{blue}[+] Load the first list.{reset}' + _file)
            elif os.path.exists('wordlist/%s' % self.options.file):
                _file = 'wordlist/%s' % self.options.file
                self.messageQueue.put(
                    f'{bold}{blue}[+] Load the first list.{reset}' + _file)
            else:
                self.messageQueue.put(
                    f'{bold}{red}[ERROR] [WORDLIST] Oops! File not exists {reset}: %s' % self.options.file)
                return

        self.messageQueue.put(f'{bold}{blue}[+] Prepare the wildcard.')
        self.messageQueue.put('[+] DONE.')
        self.messageQueue.put('[+] Search for subdomains. {reset}\n')

        normalLines = []
        worldCardLines = []
        worldcardLists = []
        regexLines = []
        lines = set()

        with open(_file) as f:
            for line in f:
                sub = line.strip()

                if not sub or sub in lines:

                    continue
                lines.add(sub)
                if sub.find('{alphnum}') >= 0 or sub.find('{alpha}') >= 0 or sub.find('{num}') >= 0:

                    worldCardLines.append(sub)
                    sub = sub.replace('{alphnum}', '[a-z0-9]')
                    sub = sub.replace('{alpha}', '[a-z]')
                    sub = sub.replace('{num}', '[0-9]')
                    if sub not in worldcardLists:

                        worldcardLists.append(sub)

                        regexLines.append('^' + sub + '$')
                else:
                    normalLines.append(sub)
        pattern = '|'.join(regexLines)
        if pattern:
            _regex = re.compile(pattern)
            if _regex:
                for line in normalLines:
                    if _regex.search(line):
                        normalLines.remove(line)
        listSubdomains = []
        groupSize = 1 if not self.options.fullScan else 1

        for item in normalLines:
            listSubdomains.append(item)
            if len(listSubdomains) >= groupSize:
                self.queue.put(listSubdomains)
                listSubdomains = []

        subdomainQueue = queue.LifoQueue()
        for line in worldCardLines:
            subdomainQueue.put(line)
            while subdomainQueue.qsize() > 0:

                item = subdomainQueue.get()
                if item.find('{alphnum}') >= 0:
                    for _letter in 'abcdefghijklmnopqrstuvwxyz0123456789':
                        subdomainQueue.put(
                            item.replace('{alphnum}', _letter, 1))
                elif item.find('{alpha}') >= 0:
                    for _letter in 'abcdefghijklmnopqrstuvwxyz':
                        subdomainQueue.put(item.replace('{alpha}', _letter, 1))
                elif item.find('{num}') >= 0:
                    for _letter in '0123456789':
                        subdomainQueue.put(item.replace('{num}', _letter, 1))
                else:
                    listSubdomains.append(item)
                    if len(listSubdomains) >= groupSize:
                        while self.queue.qsize() > 10000:
                            time.sleep(0.1)
                        self.queue.put(listSubdomains)
                        listSubdomains = []
        if listSubdomains:
            self.queue.put(listSubdomains)

    def loadSecoundSubNames(self):
    
        _file = 'wordlist/next_names.txt' if not self.options.fullScan else 'wordlist/next_names_full.txt'

        self.messageQueue.put(
            f'\n{bold}{blue}[+] Load the second list.{reset}' + _file)
        nextSubdomain = []

        with open(_file) as f:
            for line in f:
                sub = line.strip()
                if sub and sub not in nextSubdomain:
                    tmpSet = {sub}
                    while len(tmpSet) > 0:
                        item = tmpSet.pop()
                        if item.find('{alphnum}') >= 0:
                            for _letter in 'abcdefghijklmnopqrstuvwxyz0123456789':
                                tmpSet.add(item.replace(
                                    '{alphnum}', _letter, 1))
                        elif item.find('{alpha}') >= 0:
                            for _letter in 'abcdefghijklmnopqrstuvwxyz':
                                tmpSet.add(item.replace(
                                    '{alpha}', _letter, 1))
                        elif item.find('{num}') >= 0:
                            for _letter in '0123456789':
                                tmpSet.add(item.replace('{num}', _letter, 1))
                        elif item not in nextSubdomain:
                            nextSubdomain.append(item)
        self.nextSubdomain = nextSubdomain

    def updateScanCountFunction(self):
        self.lastScanned = time.time()
        self.scanCount += 1

    def updateFoundCount(self):

        self.foundCount += 1

    def printMessageFunction(self):
        while not self.stopScan:
            try:

                _msg = self.messageQueue.get(timeout=0.1)
            except:
                continue
            if _msg == 'status':
                msg = ' %s  | Found %s subdomains | %s groups left | %s scanned in %.1f seconds| %s threads' % (
                    self.subdomainWordlist, self.foundCount, self.queue.qsize(
                    ), self.scanCount, time.time() - self.startTime,
                    self.threadCount)

                sys.stdout.write(
                    '\r' + ' ' * (self.consoleWidth - len(msg)) + msg)
            elif _msg.startswith(f'{bold}{blue}[+] Check DNS Server{reset}'):

                sys.stdout.write('\r' + _msg + ' ' *
                                 (self.consoleWidth - len(_msg)))
            else:

                sys.stdout.write('\r' + _msg + ' ' *
                                 (self.consoleWidth - len(_msg)) + '\n')
            sys.stdout.flush()

    def _scan(self):
        threadId = int(threading.currentThread().getName())
        self.resolvers[threadId].nameservers = [
            self.dnsServices[threadId % self.dnsCount]]
        _listSubdomains = []
        self.lock.acquire()
        self.threadCount += 1
        self.lock.release()

        while not self.stopScan:
            if not _listSubdomains:
                try:

                    _listSubdomains = self.queue.get(timeout=0.1)
                except:
                    if time.time() - self.lastScanned > 2.0:
                        break
                    else:
                        continue

            sub = _listSubdomains.pop()

            _sub = sub.split('.')[-1]

            _sub_timeout_count = 0
            while not self.stopScan:
                try:
                    curSubDomainsLst = sub + '.' + self.target
                    self.subdomainWordlist = curSubDomainsLst
                    self.updateScanCountFunction()
                    self.messageQueue.put('status')
                    try:

                        answers = self.resolvers[threadId].query(
                            curSubDomainsLst)

                    except dns.resolver.NoAnswer as e:
                        answers = self.exResolver.query(curSubDomainsLst)

                    isWildCardRecord = False

                    if answers:
                        ips = ', '.join(
                            sorted([answer.address for answer in answers]))
                        if ips in ['192.168.1.1', '127.0.0.1', '0.0.0.0']:
                            break
                        if (_sub, ips) not in self.ipDictonary:
                            self.ipDictonary[(_sub, ips)] = 1
                        else:
                            self.ipDictonary[(_sub, ips)] += 1
                        if ips not in self.ipDictonary:
                            self.ipDictonary[ips] = 1
                        else:
                            self.ipDictonary[ips] += 1
                        if self.ipDictonary[(_sub, ips)] > 3 or self.ipDictonary[ips] > 6:
                            isWildCardRecord = True
                        if isWildCardRecord:
                            break
                        if (not self.ignoreInternet) or (not isInternet(answers[0].address)):
                            self.updateFoundCount()

                            msg = curSubDomainsLst.ljust(50) + ips
                            self.messageQueue.put(msg)
                            self.messageQueue.put('status')
                            self.outfile.write(curSubDomainsLst.ljust(
                                50) + '\t' + ips + '\n')
                            self.outfile.flush()
                            try:
                                self.resolvers[threadId].query(
                                    'lordneostark.' + curSubDomainsLst)
                            except dns.resolver.NXDOMAIN as e:
                                _lst = []
                                if_put_one = (self.queue.qsize()
                                              < self.dnsCount * 5)
                                for i in self.nextSubdomain:
                                    _lst.append(i + '.' + sub)
                                    if if_put_one:
                                        self.queue.put(_lst)
                                        _lst = []
                                    elif len(_lst) >= 10:
                                        self.queue.put(_lst)
                                        _lst = []
                                if _lst:
                                    self.queue.put(_lst)
                            except:
                                pass
                        break
                except (dns.resolver.NXDOMAIN, dns.name.EmptyLabel) as e:
                    break
                except (dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
                    _sub_timeout_count += 1
                    if _sub_timeout_count >= 6:

                        break
                except Exception as e:
                    with open('errors.log', 'a') as errFile:
                        errFile.write('%s [%s] %s %s\n' % (
                            threading.current_thread, type(e), curSubDomainsLst, e))
                    break
        self.lock.acquire()
        self.threadCount -= 1
        self.lock.release()
        self.messageQueue.put('status')

    def run(self):
        self.startTime = time.time()

        for i in range(self.options.threads):
            try:

                t = threading.Thread(target=self._scan, name=str(i))
                t.setDaemon(True)
                t.start()
            except:
                pass
        while self.threadCount > 0:
            try:
                time.sleep(0.1)
            except KeyboardInterrupt as e:
                msg = (f'{bold}{red}[WARNING] User aborted.{reset}')
                sys.stdout.write('\r' + msg + ' ' *
                                 (self.consoleWidth - len(msg)) + '\n\r')
                sys.stdout.flush()
                self.stopScan = True
        self.stopScan = True

#!/usr/bin/env python

import nmap

scanner = nmap.PortScanner()

class Scanning:
    def __init__(self,ipaddress,ports):
        self.ipaddress = ipaddress
        self.ports = ports


class Portscan(Scanning):
    def results(self):
        scanner.scan(self.ipaddress,self.ports)
        hostRange = scanner.all_hosts()
        for host in hostRange:
            print('Host: %s (%s)' %(host,scanner[host].hostname()))
            for proto in scanner[host].all_protocols():
                print('Protocol: %s' % proto)
                scannedPorts = scanner[host][proto].keys()
                for port in scannedPorts:
                    print('Port: %s\tState: %s' % (port,scanner[host][proto][port]['state']))


class Stealthscan(Scanning):
    def results(self):
        scanner.scan(self.ipaddress,self.ports,arguments='-sS')
        hostRange = scanner.all_hosts()
        for host in hostRange:
            print('Host: %s (%s)' %(host,scanner[host].hostname()))
            for proto in scanner[host].all_protocols():
                print('Protocol: %s' % proto)
                scannedPorts = scanner[host][proto].keys()
                for port in scannedPorts:
                    print('Port: %s\tState: %s' % (port,scanner[host][proto][port]['state']))

class UDPScan(Scanning):
    def results(self):
        test = scanner.scan(self.ipaddress,self.ports,arguments='-sU')
        print(test)

class Sigtran(Scanning):
    def results(self):
        test = scanner.scan(self.ipaddress,self.ports,arguments='-sY')
        print(test)


class Nullscan(Scanning):
    def results(self):
        test = scanner.scan(self.ipaddress,self.ports,arguments='-sN')
        print(test)


class Finnscan(Scanning):
    def results(self):
        test = scanner.scan(self.ipaddress,self.ports,arguments='-sF')
        print(test)

class Xmasscan(Scanning):
    def results(self):
        test = scanner.scan(self.ipaddress,self.ports,arguments='-sX')
        print(test)

class TCPAckscan(Scanning):
    def results(self):
        test = scanner.scan(self.ipaddress,self.ports,arguments='-sA')
        print(test)

class Cookiescan(Scanning):
    def results(self):
        test = scanner.scan(self.ipaddress,self.ports,arguments='-sZ')
        print(test)

class IPscan(Scanning):
    def results(self):
        test = scanner.scan(self.ipaddress,self.ports,arguments='-sO')
        print(test)
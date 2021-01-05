#!/usr/bin/env python

#import required modules
import nmap
#Set the scanner for the nmap module
scanner = nmap.PortScanner()

#set the scanning class to take in the ipaddress and port
class Scanning:
    def __init__(self,ipaddress,ports):
        self.ipaddress = ipaddress
        self.ports = ports

#Set the TCP port scan
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
                    print('Product: %s\tVersion: %s' % (scanner[host][proto][port]['product'],scanner[host][proto][port]['version']))
                    print('Extra Info: %s' % (scanner[host][proto][port]['extrainfo']))

#Set the stealth scan
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

#Set the UDP scan
class UDPScan(Scanning):
    def results(self):
        test = scanner.scan(self.ipaddress,self.ports,arguments='-sU')
        print(test)

#Set the SCTP scan
class Sigtran(Scanning):
    def results(self):
        test = scanner.scan(self.ipaddress,self.ports,arguments='-sY')
        print(test)

#Set the Null scan
class Nullscan(Scanning):
    def results(self):
        test = scanner.scan(self.ipaddress,self.ports,arguments='-sN')
        print(test)

#Set the Fin scan
class Finnscan(Scanning):
    def results(self):
        test = scanner.scan(self.ipaddress,self.ports,arguments='-sF')
        print(test)

        
#Set teh Xmas scan
class Xmasscan(Scanning):
    def results(self):
        test = scanner.scan(self.ipaddress,self.ports,arguments='-sX')
        print(test)

#Set the TCP/ACK scan
class TCPAckscan(Scanning):
    def results(self):
        test = scanner.scan(self.ipaddress,self.ports,arguments='-sA')
        print(test)

#Advanced SCTP
class Cookiescan(Scanning):
    def results(self):
        test = scanner.scan(self.ipaddress,self.ports,arguments='-sZ')
        print(test)

#Set IP Scan
class IPscan(Scanning):
    def results(self):
        test = scanner.scan(self.ipaddress,self.ports,arguments='-sO')
        print(test)

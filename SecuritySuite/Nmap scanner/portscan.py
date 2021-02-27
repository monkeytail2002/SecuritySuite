#!/usr/bin/env python


import nmap
import json

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
#		print(self.scantype)
#		print(self.ports)
#		print(self.ipaddress)
		scan = scanner.scan(self.ipaddress,self.ports,arguments='-sT')
		test_array=[]
		hostRange = scanner.all_hosts()
		for host in hostRange:
#			print('Host: %s (%s)' %(host,scanner[host].hostname()))
			test_array.append(host)
			test_array.append(scanner[host].hostname())
			for proto in scanner[host].all_protocols():
#				print('Protocol: %s' % proto)
				test_array.append(proto)
				scannedPorts = scanner[host][proto].keys()
				for port in scannedPorts:
#					print('Port: %s\tState: %s' % (port,scanner[host][proto][port]['state']))
					test_array.append(port)
					test_array.append(scanner[host][proto][port]['state'])
					print (test_array)

					
#Set the stealth scan
class Stealthscan(Scanning):
	def testresult(self):
		scan = scanner.scan(self.ipaddress,self.ports,arguments='-sS')
#		print(scan)
		hostRange = scanner.all_hosts()
		for host in hostRange:
			print('Host: %s (%s)' %(host,scanner[host].hostname()))
			for proto in scanner[host].all_protocols():
				print('Protocol: %s' % proto)
				scannedPorts = scanner[host][proto].keys()
				for port in scannedPorts:
					print('Port: %s\tState: %s' % (port,scanner[host][proto][port]['state']))
					
					
#Set the UDP scan
#class UDPScan(Scanning):
#	print("test UDP")
#    def results(self):
#		print("test udp 2")
#        scan = scanner.scan(self.ipaddress,self.ports,arguments='-sU')
#		print(scan)
#        hostRange = scanner.all_hosts()
#        for host in hostRange:
#            print('Host: %s (%s)' %(host,scanner[host].hostname()))
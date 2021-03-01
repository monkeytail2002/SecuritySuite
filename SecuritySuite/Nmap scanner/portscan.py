#!/usr/bin/env python


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
	def tcp_results(self):
		test_scan = scanner.scan(self.ipaddress, arguments='-sT')
#		print (test_scan)
		returned_list=[]
		returned_list.append(test_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(test_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(test_scan["nmap"]["scanstats"]["totalhosts"])
		hostRange = scanner.all_hosts()
		for host in hostRange:
			returned_list.append(host)
			returned_list.append(scanner[host].hostname())
			returned_list.append(scanner[host]["status"]["state"])
			for proto in scanner[host].all_protocols():
				returned_list.append(proto)
				scannedPorts = scanner[host][proto].keys()
				for port in scannedPorts:
					returned_list.append(port)
					returned_list.append(scanner[host][proto][port]["state"])
					returned_list.append(scanner[host][proto][port]["name"])
					print(returned_list)

					
#Set the stealth scan
class Stealthscan(Scanning):
	def stealth_result(self):
		scan = scanner.scan(self.ipaddress,self.ports,arguments='-sS')
#		print(scan)
		returned_list=[]
		returned_list.append(scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(scan["nmap"]["scanstats"]["totalhosts"])
		hostRange = scanner.all_hosts()
		for host in hostRange:
			returned_list.append(host)
			returned_list.append(scanner[host].hostname())
			returned_list.append(scanner[host]["status"]["state"])
			for proto in scanner[host].all_protocols():
				returned_list.append(proto)
				scannedPorts = scanner[host][proto].keys()
				for port in scannedPorts:
					returned_list.append(port)
					returned_list.append(scanner[host][proto][port]["state"])
					returned_list.append(scanner[host][proto][port]["name"])
					print(returned_list)

					
#Set the UDP scan
class UDPScan(Scanning):
	def udp_results(self):
#		print("UDP")
		udp_scan = scanner.scan(self.ipaddress,self.ports,arguments='-sU')
#		print(udp_scan)
		returned_list=[]
		returned_list.append(scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(scan["nmap"]["scanstats"]["totalhosts"])
		hostRange = scanner.all_hosts()
		for host in hostRange:
			returned_list.append(host)
			returned_list.append(scanner[host].hostname())
			returned_list.append(scanner[host]["status"]["state"])
			for proto in scanner[host].all_protocols():
				returned_list.append(proto)
				scannedPorts = scanner[host][proto].keys()
				for port in scannedPorts:
					returned_list.append(port)
					returned_list.append(scanner[host][proto][port]["state"])
					returned_list.append(scanner[host][proto][port]["name"])
					print(returned_list)

#
#class Sigtran(Scanning):
#	#	print("test Sigtran")
#    def results(self):
##		scan = scanner.scan(self.ipaddress,self.ports,arguments='-sY')
##		print(scan)
##		test_array=[]
##		hostRange = scanner.all_hosts()
##		for host in hostRange:
##			test_array.append(host)
##			test_array.append(scanner[host].hostname())
##			for proto in scanner[host].all_protocols():
##				test_array.append(proto)
##				scannedPorts = scanner[host][proto].keys()
##				for port in scannedPorts:
##					test_array.append(port)
##					test_array.append(scanner[host][proto][port]['state'])
##					print (test_array)
#
#
#class Nullscan(Scanning):
##	print("test Nullscan")
#	def results(self):
##		scan = scanner.scan(self.ipaddress,self.ports,arguments='-sN')
##		print(scan)
##		test_array=[]
##		hostRange = scanner.all_hosts()
##		for host in hostRange:
##			test_array.append(host)
##			test_array.append(scanner[host].hostname())
##			for proto in scanner[host].all_protocols():
##				test_array.append(proto)
##				scannedPorts = scanner[host][proto].keys()
##				for port in scannedPorts:
##					test_array.append(port)
##					test_array.append(scanner[host][proto][port]['state'])
##					print (test_array)
#
#class Finnscan(Scanning):
##	print("test Finnscan")
#	def results(self):
##		scan = scanner.scan(self.ipaddress,self.ports,arguments='-sF')
##		test_array=[]
##		hostRange = scanner.all_hosts()
##		for host in hostRange:
##			test_array.append(host)
##			test_array.append(scanner[host].hostname())
##			for proto in scanner[host].all_protocols():
##				test_array.append(proto)
##				scannedPorts = scanner[host][proto].keys()
##				for port in scannedPorts:
##					test_array.append(port)
##					test_array.append(scanner[host][proto][port]['state'])
##					print (test_array)
#
#
#class Xmasscan(Scanning):
##	print("test Xmasscan")
#	def results(self):
##		scan = scanner.scan(self.ipaddress,self.ports,arguments='-sX')
##		print(scan)
##		test_array=[]
##		hostRange = scanner.all_hosts()
##		for host in hostRange:
##			test_array.append(host)
##			test_array.append(scanner[host].hostname())
##			for proto in scanner[host].all_protocols():
##				test_array.append(proto)
##				scannedPorts = scanner[host][proto].keys()
##				for port in scannedPorts:
##					test_array.append(port)
##					test_array.append(scanner[host][proto][port]['state'])
##					print (test_array)
#					
#class TCPAckscan(Scanning):
##	print("test TCPAckscan")
#	def results(self):
##		scan = scanner.scan(self.ipaddress,self.ports,arguments='-sA')
##		print(scan)
##		test_array=[]
##		hostRange = scanner.all_hosts()
##		for host in hostRange:
##			test_array.append(host)
##			test_array.append(scanner[host].hostname())
##			for proto in scanner[host].all_protocols():
##				test_array.append(proto)
##				scannedPorts = scanner[host][proto].keys()
##				for port in scannedPorts:
##					test_array.append(port)
##					test_array.append(scanner[host][proto][port]['state'])
##					print (test_array)
#
#
#class Cookiescan(Scanning):
#	#	print("test Cookiescan")
#	def results(self):
##		scan = scanner.scan(self.ipaddress,self.ports,arguments='-sZ')
##		print(scan)
##		test_array=[]
##		hostRange = scanner.all_hosts()
##		for host in hostRange:
##			test_array.append(host)
##			test_array.append(scanner[host].hostname())
##			for proto in scanner[host].all_protocols():
##				test_array.append(proto)
##				scannedPorts = scanner[host][proto].keys()
##				for port in scannedPorts:
##					test_array.append(port)
##					test_array.append(scanner[host][proto][port]['state'])
##					print (test_array)
#	
#	
#class IPscan(Scanning):
#	#	print("test IPscan")
#	def results(self):
##		scan = scanner.scan(self.ipaddress,self.ports,arguments='-sO')
##		print(scan)
##		test_array=[]
##		hostRange = scanner.all_hosts()
##		for host in hostRange:
##			test_array.append(host)
##			test_array.append(scanner[host].hostname())
##			for proto in scanner[host].all_protocols():
##				test_array.append(proto)
##				scannedPorts = scanner[host][proto].keys()
##				for port in scannedPorts:
##					test_array.append(port)
##					test_array.append(scanner[host][proto][port]['state'])
##					print (test_array)
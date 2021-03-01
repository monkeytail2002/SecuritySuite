#!/usr/bin/env python

#Developed by Angus MacDonald(15009351) as part of the UG409758 Team Project module for BSc Computing Science.
#Tutor: Graeme Martindale
#Members of team: 15009351, 
#Version: 2.10 Date Completed and fully tested: 1/3/21

#Import required modules
import nmap

#Set the scanner for the nmap module
scanner = nmap.PortScanner()

#set the scanning class to take in the ipaddress and port from the nmapscan.py file
class Scanning:
	def __init__(self,ipaddress,ports):
		self.ipaddress = ipaddress
		self.ports = ports
		
#Set the TCP port scan
class Portscan(Scanning):
	def tcp_results(self):
#        print("port")
		port_scan = scanner.scan(self.ipaddress, arguments='-sT')
#		print (port_scan)
#       Create the empty list
		returned_list=[]
#    Append results to list
		returned_list.append(port_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(port_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(port_scan["nmap"]["scanstats"]["totalhosts"])
#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			returned_list.append(host)
			returned_list.append(scanner[host].hostname())
			returned_list.append(scanner[host]["status"]["state"])
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				returned_list.append(proto)
				scannedPorts = scanner[host][proto].keys()
#                Iterate through for loop for information per port
				for port in scannedPorts:
					returned_list.append(port)
					returned_list.append(scanner[host][proto][port]["state"])
					returned_list.append(scanner[host][proto][port]["reason"])
					returned_list.append(scanner[host][proto][port]["name"])
#                print the list so that it can be manipulated in php
				print(returned_list)

					
#Set the stealth scan
class Stealthscan(Scanning):
	def stealth_result(self):
		print("Stealth")
		stealth_scan = scanner.scan(self.ipaddress,self.ports,arguments='-sS')
#		print(stealth_scan)
		returned_list=[]
		returned_list.append(stealth_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(stealth_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(stealth_scan["nmap"]["scanstats"]["totalhosts"])
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
					returned_list.append(scanner[host][proto][port]["reason"])
					returned_list.append(scanner[host][proto][port]["name"])
				print(returned_list)

					
#Set the UDP scan
class UDPScan(Scanning):
	def udp_results(self):
#		print("UDP")
		udp_scan = scanner.scan(self.ipaddress,self.ports,arguments='-sU')
#		print(udp_scan)
		returned_list=[]
		returned_list.append(udp_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(udp_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(udp_scan["nmap"]["scanstats"]["totalhosts"])
		hostRange = scanner.all_hosts()
		for host in hostRange:
			returned_list.append(host)
			returned_list.append(scanner[host].hostname())
			returned_list.append(scanner[host]["status"]["state"])
		print(returned_list)

class Sigtran(Scanning):
#	print("test Sigtran")
	def sigtran_results(self):
		sig_scan = scanner.scan(self.ipaddress,self.ports,arguments='-sY')
#		print(sig_scan)
		returned_list=[]
		returned_list.append(sig_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(sig_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(sig_scan["nmap"]["scanstats"]["totalhosts"])
		hostRange = scanner.all_hosts()
		for host in hostRange:
			returned_list.append(host)
			returned_list.append(scanner[host].hostname())
			returned_list.append(scanner[host]["status"]["state"])
		print(returned_list)


class Nullscan(Scanning):
#	print("test Nullscan")
	def null_results(self):
		null_scan = scanner.scan(self.ipaddress,self.ports,arguments='-sN')
#		print(null_scan)
		returned_list=[]
		returned_list.append(null_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(null_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(null_scan["nmap"]["scanstats"]["totalhosts"])
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
					returned_list.append(scanner[host][proto][port]["reason"])
					returned_list.append(scanner[host][proto][port]["name"])
				print(returned_list)

class Finnscan(Scanning):
#	print("test Finnscan")
	def finn_results(self):
		finn_scan = scanner.scan(self.ipaddress,self.ports,arguments='-sF')
#		print(finn_scan)
		returned_list=[]
		returned_list.append(finn_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(finn_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(finn_scan["nmap"]["scanstats"]["totalhosts"])
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
					returned_list.append(scanner[host][proto][port]["reason"])
					returned_list.append(scanner[host][proto][port]["name"])
				print(returned_list)


class Xmasscan(Scanning):
#	print("test Xmasscan")
	def xmas_results(self):
		xmas_scan = scanner.scan(self.ipaddress,self.ports,arguments='-sX')
#		print(xmas_scan)
		returned_list=[]
		returned_list.append(xmas_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(xmas_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(xmas_scan["nmap"]["scanstats"]["totalhosts"])
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
					returned_list.append(scanner[host][proto][port]["reason"])
					returned_list.append(scanner[host][proto][port]["name"])
				print(returned_list)


class TCPAckscan(Scanning):
#	print("test TCPAckscan")
	def tcpackscan_results(self):
		tcpack_scan = scanner.scan(self.ipaddress,self.ports,arguments='-sA')
		print(tcpack_scan)
		returned_list=[]
		returned_list.append(tcpack_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(tcpack_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(tcpack_scan["nmap"]["scanstats"]["totalhosts"])
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
					returned_list.append(scanner[host][proto][port]["reason"])
					returned_list.append(scanner[host][proto][port]["name"])
				print(returned_list)


class Cookiescan(Scanning):
#	print("test Cookiescan")
	def cookie_results(self):
		cookie_scan = scanner.scan(self.ipaddress,self.ports,arguments='-sZ')
#		print(cookie_scan)
		returned_list=[]
		returned_list.append(cookie_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(cookie_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(cookie_scan["nmap"]["scanstats"]["totalhosts"])
		hostRange = scanner.all_hosts()
		for host in hostRange:
			returned_list.append(host)
			returned_list.append(scanner[host].hostname())
			returned_list.append(scanner[host]["status"]["state"])
			returned_list.append(scanner[host]["status"]["reason"])
		print(returned_list)
	
	
class IPscan(Scanning):
#	print("test IPscan")
	def ipscan_results(self):
		ipscan_scan = scanner.scan(self.ipaddress,self.ports,arguments='-sO')
#		print(ipscan_scan)
		returned_list=[]
		returned_list.append(ipscan_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(ipscan_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(ipscan_scan["nmap"]["scanstats"]["totalhosts"])
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
					returned_list.append(scanner[host][proto][port]["reason"])
					returned_list.append(scanner[host][proto][port]["name"])
				print(returned_list)


#!/usr/bin/env python

#Developed by Angus MacDonald(15009351) as part of the UG409758 Team Project module for BSc Computing Science.
#Tutor: Graeme Martindale
#Members of team: Angus MacDonald 15009351, Jordan L 15009237, 
#Version: 2.30 Date Completed and fully tested: 16/3/21

#Import required modules
import nmap
import json
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
#		print("port")
		port_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sT')
#		print (port_scan)
#       Create the empty list
		return_list=[]
		host_list=[]
		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			host_list.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
#            Iterate through a for loop to return the protocol
			protocol_list=[]
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				protocol_list.append({'protocols':proto})
				port_list=[]
#                Iterate through for loop for information per port
				for port in scannedPorts:
					port_list.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"]})
				protocol_list[-1]['portlist'] = port_list
			host_list[-1]['protocollist'] = protocol_list
		return_list.append({'uphosts': port_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':port_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':port_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':host_list})
		
		portscan = json.dumps(return_list)
		
		print (portscan)
		
					
#Set the stealth scan
class Stealthscan(Scanning):
	def stealth_result(self):
#		print("Stealth")
		stealth_scan = scanner.scan(self.ipaddress,self.ports,arguments='-sS')
#		print(stealth_scan)
		stealth_list=[]
		stealth_host=[]
		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			stealth_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			stealth_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				stealth_protocol.append({'protocols':proto})
				stealth_ports=[]
#                Iterate through for loop for information per port
				for port in scannedPorts:
					stealth_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"]})
				stealth_protocol[-1]['portlist'] = stealth_ports
			stealth_host[-1]['protocollist'] = stealth_protocol
		stealth_list.append({'uphosts': stealth_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':stealth_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':stealth_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':stealth_host})

		
		stealth = json.dumps(stealth_list)
		print (stealth)

					
#Set the UDP scan
class UDPScan(Scanning):
	def udp_results(self):
#		print("UDP")
		udp_scan = scanner.scan(self.ipaddress,self.ports,arguments='-sU')
#		print(udp_scan)
		udp_list=[]
		udp_host=[]
#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			udp_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state': scanner[host]["status"]["state"], 'reason': scanner[host]["status"]["reason"]})
		udp_list.append({'uphosts': udp_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':udp_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':udp_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':udp_host})

		udp = json.dumps(udp_list)
		print (udp)


class Sigtran(Scanning):
#	print("test Sigtran")
	def sigtran_results(self):
		sig_scan = scanner.scan(self.ipaddress,self.ports,arguments='-sY')
#		print(sig_scan)
		sig_list=[]
		sig_host=[]
#       Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			sig_host.append({'host':host, 'hostname': scanner[host].hostname(), 'address':scanner[host]["addresses"],'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
		sig_list.append({'uphosts': sig_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':sig_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':sig_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':sig_host})

		sig = json.dumps(sig_list)
		print (sig)


class Nullscan(Scanning):
#	print("test Nullscan")
	def null_results(self):
		null_scan = scanner.scan(self.ipaddress,self.ports,arguments='-sN')
#		print(null_scan)
		null_list=[]
		null_host=[]
		null_protocol=[]
		null_ports=[]
		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			null_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			null_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				null_protocol.append({'protocols':proto})
				null_ports=[]
#                Iterate through for loop for information per port
				for port in scannedPorts:
					null_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"]})
				null_protocol[-1]['portlist'] = null_ports
			null_host[-1]['protocollist'] = null_protocol
		null_list.append({'uphosts': null_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':null_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':null_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':null_host})

		null = json.dumps(null_list)
		print (null)


class Finnscan(Scanning):
#	print("test Finnscan")
	def finn_results(self):
		finn_scan = scanner.scan(self.ipaddress,self.ports,arguments='-sF')
#		print(finn_scan)
		finn_list=[]
		finn_host=[]
		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			finn_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			finn_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				finn_protocol.append({'protocols':proto})
				finn_ports=[]
#                Iterate through for loop for information per port
				for port in scannedPorts:
					finn_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"]})
				finn_protocol[-1]['portlist'] = finn_ports
			finn_host[-1]['protocollist'] = finn_protocol
		finn_list.append({'uphosts': finn_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':finn_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':finn_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':finn_host})

		finn = json.dumps(finn_list)
		print (finn)



class Xmasscan(Scanning):
#	print("test Xmasscan")
	def xmas_results(self):
		xmas_scan = scanner.scan(self.ipaddress,self.ports,arguments='-sX')
#		print(xmas_scan)
		xmas_list=[]
		xmas_host=[]
		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			xmas_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			xmas_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				xmas_protocol.append({'protocols':proto})
				xmas_ports=[]
#                Iterate through for loop for information per port
				for port in scannedPorts:
					xmas_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"]})
				xmas_protocol[-1]['portlist'] = xmas_ports
			xmas_host[-1]['protocollist'] = xmas_protocol
		xmas_list.append({'uphosts': xmas_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':xmas_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':xmas_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':xmas_host})

		xmas = json.dumps(xmas_list)
		print (xmas)


class TCPAckscan(Scanning):
#	print("test TCPAckscan")
	def tcpackscan_results(self):
		tcpack_scan = scanner.scan(self.ipaddress,self.ports,arguments='-sA')
#		print(tcpack_scan)
		tcpack_list=[]
		tcpack_host=[]

		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			tcpack_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			tcpack_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				tcpack_protocol.append({'protocols':proto})
				tcpack_ports=[]
#                Iterate through for loop for information per port
				for port in scannedPorts:
					tcpack_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"]})
				tcpack_protocol[-1]['portlist'] = tcpack_ports
			tcpack_host[-1]['protocollist'] = tcpack_protocol
		tcpack_list.append({'uphosts': tcpack_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':tcpack_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':tcpack_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':tcpack_host})

		tcpack = json.dumps(tcpack_list)
		print (tcpack)



class Cookiescan(Scanning):
#	print("test Cookiescan")
	def cookie_results(self):
		cookie_scan = scanner.scan(self.ipaddress,self.ports,arguments='-sZ')
#		print(cookie_scan)
		cookie_list=[]
		cookie_host=[]

#       Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			cookie_host.append({'host':host, 'hostname': scanner[host].hostname(), 'address':scanner[host]["addresses"],'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
		cookie_list.append({'uphosts': cookie_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':cookie_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':cookie_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':cookie_host})

		cookie = json.dumps(cookie_list)
		print (cookie)



class IPscan(Scanning):
#	print("test IPscan")
	def ipscan_results(self):
		ipscan_scan = scanner.scan(self.ipaddress,self.ports,arguments='-sO')
#		print(ipscan_scan)
#       Create the empty list
		ip_list=[]
		ip_host=[]
		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			ip_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			ip_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				ip_protocol.append({'protocols':proto})
				ip_port=[]
#                Iterate through for loop for information per port
				for port in scannedPorts:
					ip_port.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"]})
				ip_protocol[-1]['portlist'] = ip_port
			ip_host[-1]['protocollist'] = ip_protocol

		ip_list.append({'uphosts': ipscan_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':ipscan_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':ipscan_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':ip_host})
		

		ip = json.dumps(ip_list)
		
		print (ip)


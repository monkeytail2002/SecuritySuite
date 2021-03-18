#!/usr/bin/env python

#Developed by Angus MacDonald(15009351) as part of the UG409758 Team Project module for BSc Computing Science.
#Tutor: Graeme Martindale
#Members of team: Angus MacDonald 15009351, Jordan L 15009237, Jim
#Version: 2.30 Date Completed and fully tested: 18/3/21

import nmap
import json

#Set the scanner for the nmap module
scanner = nmap.PortScanner()

#set the scanning class to take in the ipaddress and port
class Scanning:
	def __init__(self,ipaddress,ports):
		self.ipaddress = ipaddress
		self.ports = ports

class Bannergrab(Scanning):
	def results(self):
		#scan the ip range and insert the banner script along with the -sV (version info) and -T5 (Speed 5) options
		banner_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV -T5 -script=banner')
#		print(banner_scan)
		#       Create the empty list
		banner_list=[]
		banner_host=[]
		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			banner_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			banner_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				banner_protocol.append({'protocols':proto})
				banner_port=[]
#                Iterate through for loop for information per port
				for port in scannedPorts:
					banner_port.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"],'product':scanner[host][proto][port]["product"], 'version':scanner[host][proto][port]["version"],'cpe':scanner[host][proto][port]["cpe"]})
				banner_protocol[-1]['portlist'] = banner_port
			banner_host[-1]['protocollist'] = banner_protocol
		banner_list.append({'uphosts': banner_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':banner_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':banner_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':banner_host})
		

		banner = json.dumps(banner_list)
		print(banner)

											 
    
    
    
class Bannervuln(Scanning):
	def vuln_results(self):
		#scan the ip range and insert the banner script along with the -sV option
		vuln_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV -T5 -script=vuln')
#		print(vuln_scan)
#       Create the empty list
		vuln_list=[]
		vuln_host=[]
		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			vuln_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			vuln_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				vuln_protocol.append({'protocols':proto})
				vuln_port=[]
#                Iterate through for loop for information per port
				for port in scannedPorts:
#					Checks if the script key is in the information and appends it if it is.
					if "script" in scanner[host][proto][port]:
						vuln_port.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"],'product':scanner[host][proto][port]["product"], 'version':scanner[host][proto][port]["version"],'extrainfo': scanner[host][proto][port]["extrainfo"],'cpe':scanner[host][proto][port]["cpe"],'script': scanner[host][proto][port]["script"]})
					else:
						vuln_port.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"],'product':scanner[host][proto][port]["product"], 'version':scanner[host][proto][port]["version"],'extrainfo': scanner[host][proto][port]["extrainfo"],'cpe':scanner[host][proto][port]["cpe"]})
										 
				vuln_protocol[-1]['portlist'] = vuln_port
			vuln_host[-1]['protocollist'] = vuln_protocol
		vuln_list.append({'uphosts': vuln_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':vuln_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':vuln_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':vuln_host})
		
		vuln = json.dumps(vuln_list)
		
		print (vuln)

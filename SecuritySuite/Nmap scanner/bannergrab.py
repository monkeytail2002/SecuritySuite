#!/usr/bin/env python

#Developed by Angus MacDonald(15009351) as part of the UG409758 Team Project module for BSc Computing Science.
#Tutor: Graeme Martindale
#Members of team: Angus MacDonald 15009351, Jordan L 15009237, 
#Version: 2.10 Date Completed and fully tested: 1/3/21

import nmap


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
		print(banner_scan)
		returned_list=[]
#    Append results to list
		returned_list.append(banner_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(banner_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(banner_scan["nmap"]["scanstats"]["totalhosts"])
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
					returned_list.append(scanner[host][proto][port]["product"])
					returned_list.append(scanner[host][proto][port]["version"])
					returned_list.append(scanner[host][proto][port]["extrainfo"])
					returned_list.append(scanner[host][proto][port]["cpe"])
					#Check if the bannergrab script was run on the port, which it wont if the port is not open.
					if scanner[host][proto][port]["state"] != "open":
						print(returned_list)
					else:
						returned_list.append(scanner[host][proto][port]["script"])
						print(returned_list)
											 
    
    
    
class Bannervuln(Scanning):
	def vuln_results(self):
		#scan the ip range and insert the banner script along with the -sV option
		vuln_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV -T5 -script=vuln')
#		print(vuln_scan)
		returned_list=[]
#    Append results to list
		returned_list.append(vuln_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(vuln_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(vuln_scan["nmap"]["scanstats"]["totalhosts"])
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
					returned_list.append(scanner[host][proto][port]["product"])
					returned_list.append(scanner[host][proto][port]["version"])
					returned_list.append(scanner[host][proto][port]["extrainfo"])
					returned_list.append(scanner[host][proto][port]["cpe"])
					#Check if the bannergrab script was run on the port, which it wont if the port is not open.
					if scanner[host][proto][port]["state"] != "open":
						print(returned_list)
					else:
						returned_list.append(scanner[host][proto][port]["script"])
						print(returned_list)
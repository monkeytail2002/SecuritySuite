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

class Httpauthfinder(Scanning):
	def authfinder_results(self):
#		print ("Test http auth finder")
		port = "80"
		authfinder_scan = scanner.scan(self.ipaddress, port, arguments="-sV --script=/home/michelangelo/NSEScripts/http-auth-finder.nse")
#		print(authfinder_scan)
		returned_list=[]
#    Append results to list
		returned_list.append(authfinder_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(authfinder_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(authfinder_scan["nmap"]["scanstats"]["totalhosts"])
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
					returned_list.append(scanner[host][proto][port]["cpe"])
					if scanner[host][proto][port]["script"]:
						returned_list.append(scanner[host][proto][port]["script"])
						print(returned_list)
					else:
						returned_list.append("Nothing to run script against")
						print(returned_list)
		
class Httpauth(Scanning):
	def httpauth_results(self):
#		print ("Test http auth")
		port = "80"
		httpauth_scan = scanner.scan(self.ipaddress, port, arguments="-sV --script=/home/michelangelo/NSEScripts/http-auth.nse")
#		print(httpauth_scan)
		returned_list=[]
#    Append results to list
		returned_list.append(httpauth_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(httpauth_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(httpauth_scan["nmap"]["scanstats"]["totalhosts"])
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
					returned_list.append(scanner[host][proto][port]["cpe"])
					if scanner[host][proto][port]["script"]:
						returned_list.append(scanner[host][proto][port]["script"])
						print(returned_list)
					else:
						returned_list.append("Nothing to run script against")
						print(returned_list)


class Httpenum(Scanning):
	def Httpenum_results(self):
#		print ("Test http enum")
		port = "80"
		Httpenum_scan = scanner.scan(self.ipaddress, port, arguments="-sV --script=/home/michelangelo/NSEScripts/http-enum.nse")
#		print(Httpenum_scan)
		returned_list=[]
#    Append results to list
		returned_list.append(Httpenum_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(Httpenum_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(Httpenum_scan["nmap"]["scanstats"]["totalhosts"])
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
					returned_list.append(scanner[host][proto][port]["cpe"])
					if scanner[host][proto][port]["script"]:
						returned_list.append(scanner[host][proto][port]["script"])
						print(returned_list)
					else:
						returned_list.append("Nothing to run script against")
						print(returned_list)


class Httpmethods(Scanning):
	def Httpmethods_results(self):
#		print ("Test http methods")
		port="80"
		Httpmethods_scan = scanner.scan(self.ipaddress, port, arguments="-sV --script=/home/michelangelo/NSEScripts/http-methods.nse")
#		print(Httpmethods_scan)
		returned_list=[]
#    Append results to list
		returned_list.append(Httpmethods_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(Httpmethods_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(Httpmethods_scan["nmap"]["scanstats"]["totalhosts"])
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
					returned_list.append(scanner[host][proto][port]["cpe"])
					if scanner[host][proto][port]["script"]:
						returned_list.append(scanner[host][proto][port]["script"])
						print(returned_list)
					else:
						returned_list.append("Nothing to run script against")
						print(returned_list)


class httpsitemapgenerator(Scanning):
	def sitemap_results(self):
#		print ("Test sitemap")
		port = "80"
		sitemap_scan = scanner.scan(self.ipaddress, port, arguments="--script=/home/michelangelo/NSEScripts/http-sitemap-generator.nse")
#		print(sitemap_scan)
		returned_list=[]
#    Append results to list
		returned_list.append(sitemap_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(sitemap_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(sitemap_scan["nmap"]["scanstats"]["totalhosts"])
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
					returned_list.append(scanner[host][proto][port]["cpe"])
					if scanner[host][proto][port]["script"]:
						returned_list.append(scanner[host][proto][port]["script"])
						print(returned_list)
					else:
						returned_list.append("Nothing to run script against")
						print(returned_list)
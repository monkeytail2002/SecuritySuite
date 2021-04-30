#!/usr/bin/env python

#Developed by Angus MacDonald(15009351) as part of the UG409758 Team Project module for BSc Computing Science.
#Tutor: Graeme Martindale
#Members of team: Angus MacDonald 15009351, Jordan Laing 15009237, Jim Baird 10003644
#Version: 2.40 Date Completed and fully tested: 18/3/21


import nmap
import json


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
		authfinder_scan = scanner.scan(self.ipaddress, self.ports, arguments="-sV --script=/home/michelangelo/NSEScripts/http-auth-finder.nse")
#		print(authfinder_scan)
		authfinder_list=[]
		authfinder_host=[]
		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			authfinder_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			authfinder_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				authfinder_protocol.append({'protocols':proto})
				authfinder_ports=[]
#                Iterate through for loop for information per port
				for port in scannedPorts:
					if "script" in scanner[host][proto][port]:
						authfinder_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"],'product':scanner[host][proto][port]["product"],'version':scanner[host][proto][port]["version"],'extrainfo':scanner[host][proto][port]["extrainfo"],'cpe':scanner[host][proto][port]["cpe"],'script':scanner[host][proto][port]["script"]})
					else:
						authfinder_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"],'product':scanner[host][proto][port]["product"],'version':scanner[host][proto][port]["version"],'extrainfo':scanner[host][proto][port]["extrainfo"],'cpe':scanner[host][proto][port]["cpe"],'noscript':"No Scripts could be run against this port."})		
				authfinder_protocol[-1]['portlist'] = authfinder_ports
			authfinder_host[-1]['protocollist'] = authfinder_protocol
			
			
		authfinder_list.append({'uphosts': authfinder_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':authfinder_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':authfinder_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':authfinder_host})

		
		authfinder = json.dumps(authfinder_list)
		print (authfinder)

		
class Httpauth(Scanning):
	def httpauth_results(self):
#		print ("Test http auth")
		httpauth_scan = scanner.scan(self.ipaddress, self.ports, arguments="-sV --script=/home/michelangelo/NSEScripts/http-auth.nse --script-args 'http-auth.path=/login' ")
#		print(httpauth_scan)
		auth_list=[]
		auth_host=[]
		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			auth_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			auth_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				auth_protocol.append({'protocols':proto})
				auth_ports=[]
#                Iterate through for loop for information per port
				for port in scannedPorts:
					if "script" in scanner[host][proto][port]:
						auth_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"],'product':scanner[host][proto][port]["product"],'version':scanner[host][proto][port]["version"],'extrainfo':scanner[host][proto][port]["extrainfo"],'cpe':scanner[host][proto][port]["cpe"],'script':scanner[host][proto][port]["script"]})
					else:
						auth_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"],'product':scanner[host][proto][port]["product"],'version':scanner[host][proto][port]["version"],'extrainfo':scanner[host][proto][port]["extrainfo"],'cpe':scanner[host][proto][port]["cpe"],'noscript':"No Scripts could be run against this port."})		
				auth_protocol[-1]['portlist'] = auth_ports
			auth_host[-1]['protocollist'] = auth_protocol
			
			
		auth_list.append({'uphosts': httpauth_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':httpauth_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':httpauth_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':auth_host})

		
		auth = json.dumps(auth_list)
		print (auth)


class Httpenum(Scanning):
	def httpenum_results(self):
#		print ("Test http enum")
		httpenum_scan = scanner.scan(self.ipaddress, self.ports, arguments="-sV --script=/home/michelangelo/NSEScripts/http-enum.nse")
#		print(Httpenum_scan)
		enum_list=[]
		enum_host=[]
		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			enum_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			enum_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				enum_protocol.append({'protocols':proto})
				enum_ports=[]
#                Iterate through for loop for information per port
				for port in scannedPorts:
					if "script" in scanner[host][proto][port]:
						enum_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"],'product':scanner[host][proto][port]["product"],'version':scanner[host][proto][port]["version"],'extrainfo':scanner[host][proto][port]["extrainfo"],'cpe':scanner[host][proto][port]["cpe"],'script':scanner[host][proto][port]["script"]})
					else:
						enum_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"],'product':scanner[host][proto][port]["product"],'version':scanner[host][proto][port]["version"],'extrainfo':scanner[host][proto][port]["extrainfo"],'cpe':scanner[host][proto][port]["cpe"],'noscript':"No Scripts could be run against this port."})		
				enum_protocol[-1]['portlist'] = enum_ports
			enum_host[-1]['protocollist'] = enum_protocol
			
			
		enum_list.append({'uphosts': httpenum_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':httpenum_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':httpenum_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':enum_host})

		
		enum = json.dumps(enum_list)
		print (enum)



class Httpmethods(Scanning):
	def httpmethods_results(self):
#		print ("Test http methods")
		httpmethods_scan = scanner.scan(self.ipaddress, self.ports, arguments="-sV --script=/home/michelangelo/NSEScripts/http-methods.nse")
#		print(httpmethods_scan)
		methods_list=[]
		methods_host=[]
		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			methods_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			methods_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				methods_protocol.append({'protocols':proto})
				methods_ports=[]
#                Iterate through for loop for information per port
				for port in scannedPorts:
					if "script" in scanner[host][proto][port]:
						methods_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"],'product':scanner[host][proto][port]["product"],'version':scanner[host][proto][port]["version"],'extrainfo':scanner[host][proto][port]["extrainfo"],'cpe':scanner[host][proto][port]["cpe"],'script':scanner[host][proto][port]["script"]})
					else:
						methods_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"],'product':scanner[host][proto][port]["product"],'version':scanner[host][proto][port]["version"],'extrainfo':scanner[host][proto][port]["extrainfo"],'cpe':scanner[host][proto][port]["cpe"],'noscript':"No Scripts could be run against this port."})		
				methods_protocol[-1]['portlist'] = methods_ports
			methods_host[-1]['protocollist'] = methods_protocol
			
			
		methods_list.append({'uphosts': httpmethods_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':httpmethods_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':httpmethods_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':methods_host})

		
		methods = json.dumps(methods_list)
		print (methods)


class Httpsitemapgenerator(Scanning):
	def sitemap_results(self):
#		print ("Test sitemap")
		sitemap_scan = scanner.scan(self.ipaddress, self.ports, arguments="--script=/home/michelangelo/NSEScripts/http-sitemap-generator.nse")
#		print(sitemap_scan)
		sitemap_list=[]
		sitemap_host=[]
		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			sitemap_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			sitemap_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				sitemap_protocol.append({'protocols':proto})
				sitemap_ports=[]
#                Iterate through for loop for information per port
				for port in scannedPorts:
					if "script" in scanner[host][proto][port]:
						sitemap_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"],'product':scanner[host][proto][port]["product"],'version':scanner[host][proto][port]["version"],'extrainfo':scanner[host][proto][port]["extrainfo"],'cpe':scanner[host][proto][port]["cpe"],'script':scanner[host][proto][port]["script"]})
					else:
						sitemap_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"],'product':scanner[host][proto][port]["product"],'version':scanner[host][proto][port]["version"],'extrainfo':scanner[host][proto][port]["extrainfo"],'cpe':scanner[host][proto][port]["cpe"],'noscript':"No Scripts could be run against this port."})		
				sitemap_protocol[-1]['portlist'] = sitemap_ports
			sitemap_host[-1]['protocollist'] = sitemap_protocol
			
			
		sitemap_list.append({'uphosts': sitemap_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':sitemap_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':sitemap_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':sitemap_host})

		
		sitemap = json.dumps(sitemap_list)
		print (sitemap)
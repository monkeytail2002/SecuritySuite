#!/usr/bin/env python
#Developed by Angus MacDonald(15009351) as part of the UG409758 Team Project module for BSc Computing Science.
#Tutor: Graeme Martindale
#Members of team: Angus MacDonald 15009351, Jordan L 15009237, Jim
#Version: 2.50 Date Completed and fully tested: 18/3/21

import nmap
import json

#Set the scanner for the nmap module
scanner = nmap.PortScanner()

#set the scanning class to take in the ipaddress and port
class Scanning:
	def __init__(self,ipaddress,ports):
		self.ipaddress = ipaddress
		self.ports = ports


class Limitedos(Scanning):
	def limited_results(self):
#		print("limited")
		limited_scan = scanner.scan(self.ipaddress, arguments='-O -v --osscan-limit')
#		print(limited_scan)
		limited_list=[]
		limited_host=[]

		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			limited_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"], 'uptime':scanner[host]["uptime"]["seconds"], 'lastboot': scanner[host]["uptime"]["lastboot"]})
			limited_protocol=[]
			limited_os=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				limited_protocol.append({'protocols':proto})
#                Iterate through for loop for information per port
				limited_ports=[]
				for port in scannedPorts:
					limited_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"]})
				limited_protocol[-1]['portlist'] = limited_ports
			limited_host[-1]['protocollist'] = limited_protocol
			
			for os in scanner[host]["osmatch"]:
				limited_os.append({'name': os["name"], 'accuracy': os["accuracy"]})
				limited_match = []
				for match in os["osclass"]:
					limited_match.append({'type': match["type"], 'vendor': match["vendor"], 'osfamily': match["osfamily"], 'osgen': match["osgen"], 'matchaccuracy': match["accuracy"], 'cpe': match["cpe"]})
				limited_os[-1]['matchlist'] = limited_match
			limited_host[-1]['oslist'] = limited_os		
			
		
		limited_list.append({'uphosts': limited_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':limited_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':limited_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':limited_host})
		
		os_limited = json.dumps(limited_list)
		print(os_limited)



class Guessos(Scanning):
	def guess_results(self):
#		print("Guess")
		guess_scan = scanner.scan(self.ipaddress, arguments='-O -v --osscan-limit')
#		print(guess_scan)
		guess_list=[]
		guess_host=[]

		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			guess_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"], 'uptime':scanner[host]["uptime"]["seconds"], 'lastboot': scanner[host]["uptime"]["lastboot"]})
			guess_protocol=[]
			guess_os=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				guess_protocol.append({'protocols':proto})
#                Iterate through for loop for information per port
				guess_ports=[]
				for port in scannedPorts:
					guess_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"]})
				guess_protocol[-1]['portlist'] =guess_ports
			guess_host[-1]['protocollist'] = guess_protocol
			
			for os in scanner[host]["osmatch"]:
				guess_os.append({'name': os["name"], 'accuracy': os["accuracy"]})
				guess_match = []
				for match in os["osclass"]:
					guess_match.append({'type': match["type"], 'vendor': match["vendor"], 'osfamily': match["osfamily"], 'osgen': match["osgen"], 'matchaccuracy': match["accuracy"], 'cpe': match["cpe"]})
				guess_os[-1]['matchlist'] = guess_match
			guess_host[-1]['oslist'] = guess_os		
			
		
		guess_list.append({'uphosts': guess_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':guess_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':guess_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':guess_host})
		
		os_guess = json.dumps(guess_list)
		print(os_guess)



class Maxoneos(Scanning):
	def maxone_results(self):
#		print("Max one")
		maxone_scan = scanner.scan(self.ipaddress, arguments='-O -v --osscan-limit')
#		print(maxone_scan)
		maxone_list=[]
		maxone_host=[]

		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			maxone_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"], 'uptime':scanner[host]["uptime"]["seconds"], 'lastboot': scanner[host]["uptime"]["lastboot"]})
			maxone_protocol=[]
			maxone_os=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				maxone_protocol.append({'protocols':proto})
#                Iterate through for loop for information per port
				maxone_ports=[]
				for port in scannedPorts:
					maxone_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"]})
				maxone_protocol[-1]['portlist'] = maxone_ports
			maxone_host[-1]['protocollist'] = maxone_protocol
			
			for os in scanner[host]["osmatch"]:
				maxone_os.append({'name': os["name"], 'accuracy': os["accuracy"]})
				maxone_match = []
				for match in os["osclass"]:
					maxone_match.append({'type': match["type"], 'vendor': match["vendor"], 'osfamily': match["osfamily"], 'osgen': match["osgen"], 'matchaccuracy': match["accuracy"], 'cpe': match["cpe"]})
				maxone_os[-1]['matchlist'] = maxone_match
			maxone_host[-1]['oslist'] = maxone_os		
			
		
		maxone_list.append({'uphosts': maxone_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':maxone_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':maxone_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':maxone_host})
		
		os_maxone = json.dumps(maxone_list)
		print(os_maxone)




class Maxtwoos(Scanning):
	def maxtwo_results(self):
#		print("Max two")
		maxtwo_scan = scanner.scan(self.ipaddress, arguments='-O -v --osscan-limit')
#		print(maxtwo_scan)
		maxtwo_list=[]
		maxtwo_host=[]

		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			maxtwo_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"], 'uptime':scanner[host]["uptime"]["seconds"], 'lastboot': scanner[host]["uptime"]["lastboot"]})
			maxtwo_protocol=[]
			maxtwo_os=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				maxtwo_protocol.append({'protocols':proto})
#                Iterate through for loop for information per port
				maxtwo_ports=[]
				for port in scannedPorts:
					maxtwo_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"]})
				maxtwo_protocol[-1]['portlist'] = maxtwo_ports
			maxtwo_host[-1]['protocollist'] = maxtwo_protocol
			
			for os in scanner[host]["osmatch"]:
				maxtwo_os.append({'name': os["name"], 'accuracy': os["accuracy"]})
				maxtwo_match = []
				for match in os["osclass"]:
					maxtwo_match.append({'type': match["type"], 'vendor': match["vendor"], 'osfamily': match["osfamily"], 'osgen': match["osgen"], 'matchaccuracy': match["accuracy"], 'cpe': match["cpe"]})
				maxtwo_os[-1]['matchlist'] = maxtwo_match
			maxtwo_host[-1]['oslist'] = maxtwo_os		
			
		
		maxtwo_list.append({'uphosts': maxtwo_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':maxtwo_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':maxtwo_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':maxtwo_host})
		
		os_maxtwo= json.dumps(maxtwo_list)
		print(os_maxtwo)



class Maxthreeos(Scanning):
	def maxthree_results(self):
#		print("Max three")
		maxthree_scan = scanner.scan(self.ipaddress, arguments='-O -v --osscan-limit')
#		print(maxthree_scan)
		maxthree_list=[]
		maxthree_host=[]

		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			maxthree_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"], 'uptime':scanner[host]["uptime"]["seconds"], 'lastboot': scanner[host]["uptime"]["lastboot"]})
			maxthree_protocol=[]
			maxthree_os=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				maxthree_protocol.append({'protocols':proto})
#                Iterate through for loop for information per port
				maxthree_ports=[]
				for port in scannedPorts:
					maxthree_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"]})
				maxthree_protocol[-1]['portlist'] = maxthree_ports
			maxthree_host[-1]['protocollist'] = maxthree_protocol
			
			for os in scanner[host]["osmatch"]:
				maxthree_os.append({'name': os["name"], 'accuracy': os["accuracy"]})
				maxthree_match = []
				for match in os["osclass"]:
					maxthree_match.append({'type': match["type"], 'vendor': match["vendor"], 'osfamily': match["osfamily"], 'osgen': match["osgen"], 'matchaccuracy': match["accuracy"], 'cpe': match["cpe"]})
				maxthree_os[-1]['matchlist'] = maxthree_match
			maxthree_host[-1]['oslist'] = maxthree_os		
			
		
		maxthree_list.append({'uphosts': maxthree_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':maxthree_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':maxthree_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':maxthree_host})
		
		os_maxthree = json.dumps(maxthree_list)
		print(os_maxthree)



class Maxfouros(Scanning):
	def maxfour_results(self):
#		print("Max four")
		maxfour_scan = scanner.scan(self.ipaddress, arguments='-O -v --osscan-limit')
#		print(maxfour_scan)
		maxfour_list=[]
		maxfour_host=[]

		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			maxfour_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"], 'uptime':scanner[host]["uptime"]["seconds"], 'lastboot': scanner[host]["uptime"]["lastboot"]})
			maxfour_protocol=[]
			maxfour_os=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				maxfour_protocol.append({'protocols':proto})
#                Iterate through for loop for information per port
				maxfour_ports=[]
				for port in scannedPorts:
					maxfour_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"]})
				maxfour_protocol[-1]['portlist'] = maxfour_ports
			maxfour_host[-1]['protocollist'] = maxfour_protocol
			
			for os in scanner[host]["osmatch"]:
				maxfour_os.append({'name': os["name"], 'accuracy': os["accuracy"]})
				maxfour_match = []
				for match in os["osclass"]:
					maxfour_match.append({'type': match["type"], 'vendor': match["vendor"], 'osfamily': match["osfamily"], 'osgen': match["osgen"], 'matchaccuracy': match["accuracy"], 'cpe': match["cpe"]})
				maxfour_os[-1]['matchlist'] = maxfour_match
			maxfour_host[-1]['oslist'] = maxfour_os		
			
		
		maxfour_list.append({'uphosts': maxfour_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':maxfour_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':maxfour_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':maxfour_host})
		
		os_maxfour = json.dumps(maxfour_list)
		print(os_maxfour)



class Maxfiveos(Scanning):
	def maxfive_results(self):
#		print("Max five")
		maxfive_scan = scanner.scan(self.ipaddress, arguments='-O -v --osscan-limit')
#		print(maxfive_scan)
		maxfive_list=[]
		maxfive_host=[]

		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			maxfive_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"], 'uptime':scanner[host]["uptime"]["seconds"], 'lastboot': scanner[host]["uptime"]["lastboot"]})
			maxfive_protocol=[]
			maxfive_os=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				maxfive_protocol.append({'protocols':proto})
#                Iterate through for loop for information per port
				maxfive_ports=[]
				for port in scannedPorts:
					maxfive_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"]})
				maxfive_protocol[-1]['portlist'] = maxfive_ports
			maxfive_host[-1]['protocollist'] = maxfive_protocol
			
			for os in scanner[host]["osmatch"]:
				maxfive_os.append({'name': os["name"], 'accuracy': os["accuracy"]})
				maxfive_match = []
				for match in os["osclass"]:
					maxfive_match.append({'type': match["type"], 'vendor': match["vendor"], 'osfamily': match["osfamily"], 'osgen': match["osgen"], 'matchaccuracy': match["accuracy"], 'cpe': match["cpe"]})
				maxfive_os[-1]['matchlist'] = maxfive_match
			maxfive_host[-1]['oslist'] = maxfive_os		
			
		
		maxfive_list.append({'uphosts': maxfive_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':maxfive_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':maxfive_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':maxfive_host})
		
		os_maxfive = json.dumps(maxfive_list)
		print(os_maxfive)
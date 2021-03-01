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


class Intensityzero(Scanning):
	def vzero_results(self):
#		print("test zero")
#		scan the ip range and ports
		zero_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 0')
#		set the scan to return the host
#		print(zero_scan)
#       Create the empty list
		returned_list=[]
#    Append results to list
		returned_list.append(zero_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(zero_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(zero_scan["nmap"]["scanstats"]["totalhosts"])
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
#                print the list so that it can be manipulated in php
				print(returned_list)



class Intensityone(Scanning):
	def vone_results(self):
#		print("test One")
#		scan the ip range and ports
		one_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 0')
#		print(one_scan)
#       Create the empty list
		returned_list=[]
#    Append results to list
		returned_list.append(one_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(one_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(one_scan["nmap"]["scanstats"]["totalhosts"])
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
#                print the list so that it can be manipulated in php
				print(returned_list)

	
class Intensitytwo(Scanning):
	def vtwo_results(self):
#		print("test Two")
#		scan the ip range and ports
		two_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 0')
#		print(two_scan)
#       Create the empty list
		returned_list=[]
#    Append results to list
		returned_list.append(two_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(two_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(two_scan["nmap"]["scanstats"]["totalhosts"])
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
#                print the list so that it can be manipulated in php
				print(returned_list)

	
class Intensitythree(Scanning):
	def vthree_results(self):
#		print("test Three")
#		scan the ip range and ports
		three_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 0')
#		print(three_scan)
#       Create the empty list
		returned_list=[]
#    Append results to list
		returned_list.append(three_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(three_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(three_scan["nmap"]["scanstats"]["totalhosts"])
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
#                print the list so that it can be manipulated in php
				print(returned_list)
	
	
	
class Intensityfour(Scanning):
	def vfour_results(self):
#		print("test Four")
#		scan the ip range and ports
		four_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 0')
#		print(four_scan)
#       Create the empty list
		returned_list=[]
#    Append results to list
		returned_list.append(four_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(four_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(four_scan["nmap"]["scanstats"]["totalhosts"])
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
#                print the list so that it can be manipulated in php
				print(returned_list)

	
class Intensityfive(Scanning):
	def vfive_results(self):
#		print("test Five")
#		scan the ip range and ports
		five_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 0')
#		print(five_scan)
#       Create the empty list
		returned_list=[]
#    Append results to list
		returned_list.append(five_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(five_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(five_scan["nmap"]["scanstats"]["totalhosts"])
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
#                print the list so that it can be manipulated in php
				print(returned_list)

	
	
class Intensitysix(Scanning):
	def vsix_results(self):
#		print("test Six")
#				scan the ip range and ports
		six_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 6')
#		print(six_scan)
#       Create the empty list
		returned_list=[]
#    Append results to list
		returned_list.append(six_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(six_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(six_scan["nmap"]["scanstats"]["totalhosts"])
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
#                print the list so that it can be manipulated in php
				print(returned_list)

	
	
class Intensityseven(Scanning):
	def vseven_results(self):
#		print("test Seven")
		#		scan the ip range and ports
		seven_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 7')
#		print(seven_scan)
#       Create the empty list
		returned_list=[]
#    Append results to list
		returned_list.append(seven_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(seven_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(seven_scan["nmap"]["scanstats"]["totalhosts"])
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
#                print the list so that it can be manipulated in php
				print(returned_list)

#
#
class Intensityeight(Scanning):
	def veight_results(self):
#		print("test Eight")
		#		scan the ip range and ports
		eight_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 8')
#		print(eight_scan)
#       Create the empty list
		returned_list=[]
#    Append results to list
		returned_list.append(eight_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(eight_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(eight_scan["nmap"]["scanstats"]["totalhosts"])
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
#                print the list so that it can be manipulated in php
				print(returned_list)

	
#
class Intensitynine(Scanning):
	def vnine_results(self):
#		print("test nine")
#		#		scan the ip range and ports
		nine_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 8')
#		print(nine_scan)
#       Create the empty list
		returned_list=[]
#    Append results to list
		returned_list.append(nine_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(nine_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(nine_scan["nmap"]["scanstats"]["totalhosts"])
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
#                print the list so that it can be manipulated in php
				print(returned_list)
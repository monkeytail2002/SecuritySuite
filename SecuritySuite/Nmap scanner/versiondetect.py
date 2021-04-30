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


class Intensityzero(Scanning):
	def vzero_results(self):
#		print("test zero")
#		scan the ip range and ports
		zero_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 0')
#		set the scan to return the host
#		print(zero_scan)
		zero_list=[]
		zero_host=[]

		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			zero_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			zero_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				zero_protocol.append({'protocols':proto})
#                Iterate through for loop for information per port
				zero_ports=[]
				for port in scannedPorts:
					zero_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"], 'product': scanner[host][proto][port]["product"], 'version':scanner[host][proto][port]["version"], 'extrainfo': scanner[host][proto][port]["extrainfo"] , 'cpe':scanner[host][proto][port]["cpe"]})
				zero_protocol[-1]['portlist'] = zero_ports
			zero_host[-1]['protocollist'] = zero_protocol
		zero_list.append({'uphosts': zero_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':zero_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':zero_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':zero_host})

		
		zero = json.dumps(zero_list)
		print(zero)



class Intensityone(Scanning):
	def vone_results(self):
#		print("test One")
#		scan the ip range and ports
		one_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 1')
#		print(one_scan)
		one_list=[]
		one_host=[]

		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			one_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			one_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				one_protocol.append({'protocols':proto})
#                Iterate through for loop for information per port
				one_ports=[]
				for port in scannedPorts:
					one_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"], 'product': scanner[host][proto][port]["product"], 'version':scanner[host][proto][port]["version"], 'extrainfo': scanner[host][proto][port]["extrainfo"] , 'cpe':scanner[host][proto][port]["cpe"]})
				one_protocol[-1]['portlist'] = one_ports
			one_host[-1]['protocollist'] = one_protocol
		one_list.append({'uphosts': one_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':one_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':one_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':one_host})

		
		one = json.dumps(one_list)
		print(one)

	
class Intensitytwo(Scanning):
	def vtwo_results(self):
#		print("test Two")
#		scan the ip range and ports
		two_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 2')
#		print(two_scan)
		two_list=[]
		two_host=[]

		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			two_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			two_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				two_protocol.append({'protocols':proto})
#                Iterate through for loop for information per port
				two_ports=[]
				for port in scannedPorts:
					two_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"], 'product': scanner[host][proto][port]["product"], 'version':scanner[host][proto][port]["version"], 'extrainfo': scanner[host][proto][port]["extrainfo"] , 'cpe':scanner[host][proto][port]["cpe"]})
				two_protocol[-1]['portlist'] = two_ports
			two_host[-1]['protocollist'] = two_protocol
		two_list.append({'uphosts': two_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':two_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':two_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':two_host})

		
		two = json.dumps(two_list)
		print(two)


	
class Intensitythree(Scanning):
	def vthree_results(self):
#		print("test Three")
#		scan the ip range and ports
		three_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 3')
#		print(three_scan)
		three_list=[]
		three_host=[]

		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			three_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			three_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				three_protocol.append({'protocols':proto})
#                Iterate through for loop for information per port
				three_ports=[]
				for port in scannedPorts:
					three_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"], 'product': scanner[host][proto][port]["product"], 'version':scanner[host][proto][port]["version"], 'extrainfo': scanner[host][proto][port]["extrainfo"] , 'cpe':scanner[host][proto][port]["cpe"]})
				three_protocol[-1]['portlist'] = three_ports
			three_host[-1]['protocollist'] = three_protocol
		three_list.append({'uphosts': three_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':three_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':three_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':three_host})

		
		three = json.dumps(three_list)
		print(three)

	
	
	
class Intensityfour(Scanning):
	def vfour_results(self):
#		print("test Four")
#		scan the ip range and ports
		four_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 4')
#		print(four_scan)
		four_list=[]
		four_host=[]

		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			four_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			four_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				four_protocol.append({'protocols':proto})
#                Iterate through for loop for information per port
				four_ports=[]
				for port in scannedPorts:
					four_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"], 'product': scanner[host][proto][port]["product"], 'version':scanner[host][proto][port]["version"], 'extrainfo': scanner[host][proto][port]["extrainfo"] , 'cpe':scanner[host][proto][port]["cpe"]})
				four_protocol[-1]['portlist'] = four_ports
			four_host[-1]['protocollist'] = four_protocol
		four_list.append({'uphosts': four_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':four_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':four_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':four_host})

		
		four = json.dumps(four_list)
		print(four)


	
class Intensityfive(Scanning):
	def vfive_results(self):
#		print("test Five")
#		scan the ip range and ports
		five_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 5')
#		print(five_scan)
		five_list=[]
		five_host=[]

		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			five_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			five_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				five_protocol.append({'protocols':proto})
#                Iterate through for loop for information per port
				five_ports=[]
				for port in scannedPorts:
					five_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"], 'product': scanner[host][proto][port]["product"], 'version':scanner[host][proto][port]["version"], 'extrainfo': scanner[host][proto][port]["extrainfo"] , 'cpe':scanner[host][proto][port]["cpe"]})
				five_protocol[-1]['portlist'] = five_ports
			five_host[-1]['protocollist'] = five_protocol
		five_list.append({'uphosts': five_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':five_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':five_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':five_host})

		
		five = json.dumps(five_list)
		print(five)


	
	
class Intensitysix(Scanning):
	def vsix_results(self):
#		print("test Six")
#				scan the ip range and ports
		six_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 6')
#		print(six_scan)
		six_list=[]
		six_host=[]

		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			six_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			six_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				six_protocol.append({'protocols':proto})
#                Iterate through for loop for information per port
				six_ports=[]
				for port in scannedPorts:
					six_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"], 'product': scanner[host][proto][port]["product"], 'version':scanner[host][proto][port]["version"], 'extrainfo': scanner[host][proto][port]["extrainfo"] , 'cpe':scanner[host][proto][port]["cpe"]})
				six_protocol[-1]['portlist'] = six_ports
			six_host[-1]['protocollist'] = six_protocol
		six_list.append({'uphosts': six_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':six_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':six_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':six_host})

		
		six = json.dumps(six_list)
		print(six)


	
	
class Intensityseven(Scanning):
	def vseven_results(self):
#		print("test Seven")
		#		scan the ip range and ports
		seven_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 7')
#		print(seven_scan)
		seven_list=[]
		seven_host=[]

		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			seven_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			seven_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				seven_protocol.append({'protocols':proto})
#                Iterate through for loop for information per port
				seven_ports=[]
				for port in scannedPorts:
					seven_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"], 'product': scanner[host][proto][port]["product"], 'version':scanner[host][proto][port]["version"], 'extrainfo': scanner[host][proto][port]["extrainfo"] , 'cpe':scanner[host][proto][port]["cpe"]})
				seven_protocol[-1]['portlist'] = seven_ports
			seven_host[-1]['protocollist'] = seven_protocol
		seven_list.append({'uphosts': seven_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':seven_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':seven_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':seven_host})

		
		seven = json.dumps(seven_list)
		print(seven)


#
#
class Intensityeight(Scanning):
	def veight_results(self):
#		print("test Eight")
		#		scan the ip range and ports
		eight_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 8')
#		print(eight_scan)
		eight_list=[]
		eight_host=[]

		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			eight_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			eight_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				eight_protocol.append({'protocols':proto})
#                Iterate through for loop for information per port
				eight_ports=[]
				for port in scannedPorts:
					eight_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"], 'product': scanner[host][proto][port]["product"], 'version':scanner[host][proto][port]["version"], 'extrainfo': scanner[host][proto][port]["extrainfo"] , 'cpe':scanner[host][proto][port]["cpe"]})
				eight_protocol[-1]['portlist'] = eight_ports
			eight_host[-1]['protocollist'] = eight_protocol
		eight_list.append({'uphosts': eight_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':eight_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':eight_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':eight_host})

		
		eight = json.dumps(eight_list)
		print(eight)


	
#
class Intensitynine(Scanning):
	def vnine_results(self):
#		print("test nine")
#		#		scan the ip range and ports
		nine_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-all')
#		print(nine_scan)
		nine_list=[]
		nine_host=[]

		#        Set scanned hosts in the range to a variable
		hostRange = scanner.all_hosts()
#        Iterate through a for loop to return the hosts, DNS entry and state of host
		for host in hostRange:
			nine_host.append({'host':host, 'hostname': scanner[host].hostname(), 'state':scanner[host]["status"]["state"],'hostreason':scanner[host]["status"]["reason"]})
			nine_protocol=[]
#            Iterate through a for loop to return the protocol
			for proto in scanner[host].all_protocols():
				scannedPorts = scanner[host][proto].keys()
				nine_protocol.append({'protocols':proto})
#                Iterate through for loop for information per port
				nine_ports=[]
				for port in scannedPorts:
					nine_ports.append({'port':port, 'portstate':scanner[host][proto][port]["state"],'portreason':scanner[host][proto][port]["reason"],'portname':scanner[host][proto][port]["name"], 'product': scanner[host][proto][port]["product"], 'version':scanner[host][proto][port]["version"], 'extrainfo': scanner[host][proto][port]["extrainfo"] , 'cpe':scanner[host][proto][port]["cpe"]})
				nine_protocol[-1]['portlist'] = nine_ports
			nine_host[-1]['protocollist'] = nine_protocol
		nine_list.append({'uphosts': nine_scan["nmap"]["scanstats"]["uphosts"], 'downhosts':nine_scan["nmap"]["scanstats"]["downhosts"], 'totalhosts':nine_scan["nmap"]["scanstats"]["totalhosts"], 'hosts':nine_host})

		nine = json.dumps(nine_list)
		print(nine)

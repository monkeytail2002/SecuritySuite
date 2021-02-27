#!/usr/bin/env python


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
	def results(self):
		print("test zero")
#		scan the ip range and ports
		scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 0')
#		set the scan to return the host
		hostRange = scanner.all_hosts()
		for host in hostRange:
			print('Target: %s (%s)' % (host, scanner[host].hostname()))
            #return the information by port
			for proto in scanner[host].all_protocols():
				print('Protocol: %s' % proto)
				scannedBanner = scanner[host][proto].keys()
				for port in scannedBanner:
					print('Port: %s' % (port))
					print('State|Reason: %s|%s' % (scanner[host][proto][port]['state'],scanner[host][proto][port]['reason']))
					print('Name: %s' % (scanner[host][proto][port]['name']))
					print('Product|Version: %s|%s' % (scanner[host][proto][port]['product'],scanner[host][proto][port]['version']))
					print('Extra Information: %s' % (scanner[host][proto][port]['extrainfo']))
					print('CPE: %s' % (scanner[host][proto][port]['cpe']))


class Intensityone(Scanning):
	def results(self):
		print("test One")
		#		scan the ip range and ports
		scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 1')
#		set the scan to return the host
		hostRange = scanner.all_hosts()
		for host in hostRange:
			print('Target: %s (%s)' % (host, scanner[host].hostname()))
            #return the information by port
			for proto in scanner[host].all_protocols():
				print('Protocol: %s' % proto)
				scannedBanner = scanner[host][proto].keys()
				for port in scannedBanner:
					print('Port: %s' % (port))
					print('State|Reason: %s|%s' % (scanner[host][proto][port]['state'],scanner[host][proto][port]['reason']))
					print('Name: %s' % (scanner[host][proto][port]['name']))
					print('Product|Version: %s|%s' % (scanner[host][proto][port]['product'],scanner[host][proto][port]['version']))
					print('Extra Information: %s' % (scanner[host][proto][port]['extrainfo']))
					print('CPE: %s' % (scanner[host][proto][port]['cpe']))

class Intensitytwo(Scanning):
	def results(self):
		print("test Two")
		#		scan the ip range and ports
		scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 2')
#		set the scan to return the host
		hostRange = scanner.all_hosts()
		for host in hostRange:
			print('Target: %s (%s)' % (host, scanner[host].hostname()))
#            #return the information by port
			for proto in scanner[host].all_protocols():
				print('Protocol: %s' % proto)
				scannedBanner = scanner[host][proto].keys()
				for port in scannedBanner:
					print('Port: %s' % (port))
					print('State|Reason: %s|%s' % (scanner[host][proto][port]['state'],scanner[host][proto][port]['reason']))
					print('Name: %s' % (scanner[host][proto][port]['name']))
					print('Product|Version: %s|%s' % (scanner[host][proto][port]['product'],scanner[host][proto][port]['version']))
					print('Extra Information: %s' % (scanner[host][proto][port]['extrainfo']))
					print('CPE: %s' % (scanner[host][proto][port]['cpe']))

class Intensitythree(Scanning):
	def results(self):
		print("test Three")
		#		scan the ip range and ports
		scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 3')
#		set the scan to return the host
		hostRange = scanner.all_hosts()
		for host in hostRange:
			print('Target: %s (%s)' % (host, scanner[host].hostname()))
#            #return the information by port
			for proto in scanner[host].all_protocols():
				print('Protocol: %s' % proto)
				scannedBanner = scanner[host][proto].keys()
				for port in scannedBanner:
					print('Port: %s' % (port))
					print('State|Reason: %s|%s' % (scanner[host][proto][port]['state'],scanner[host][proto][port]['reason']))
					print('Name: %s' % (scanner[host][proto][port]['name']))
					print('Product|Version: %s|%s' % (scanner[host][proto][port]['product'],scanner[host][proto][port]['version']))
					print('Extra Information: %s' % (scanner[host][proto][port]['extrainfo']))
					print('CPE: %s' % (scanner[host][proto][port]['cpe']))

class Intensityfour(Scanning):
	def results(self):
		print("test Four")
		#		scan the ip range and ports
		scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 4')
#		set the scan to return the host
		hostRange = scanner.all_hosts()
		for host in hostRange:
			print('Target: %s (%s)' % (host, scanner[host].hostname()))
#            #return the information by port
			for proto in scanner[host].all_protocols():
				print('Protocol: %s' % proto)
				scannedBanner = scanner[host][proto].keys()
				for port in scannedBanner:
					print('Port: %s' % (port))
					print('State|Reason: %s|%s' % (scanner[host][proto][port]['state'],scanner[host][proto][port]['reason']))
					print('Name: %s' % (scanner[host][proto][port]['name']))
					print('Product|Version: %s|%s' % (scanner[host][proto][port]['product'],scanner[host][proto][port]['version']))
					print('Extra Information: %s' % (scanner[host][proto][port]['extrainfo']))
					print('CPE: %s' % (scanner[host][proto][port]['cpe']))

class Intensityfive(Scanning):
	def results(self):
		print("test Five")
		#		scan the ip range and ports
		scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 5')
#		set the scan to return the host
		hostRange = scanner.all_hosts()
		for host in hostRange:
			print('Target: %s (%s)' % (host, scanner[host].hostname()))
#            #return the information by port
			for proto in scanner[host].all_protocols():
				print('Protocol: %s' % proto)
				scannedBanner = scanner[host][proto].keys()
				for port in scannedBanner:
					print('Port: %s' % (port))
					print('State|Reason: %s|%s' % (scanner[host][proto][port]['state'],scanner[host][proto][port]['reason']))
					print('Name: %s' % (scanner[host][proto][port]['name']))
					print('Product|Version: %s|%s' % (scanner[host][proto][port]['product'],scanner[host][proto][port]['version']))
					print('Extra Information: %s' % (scanner[host][proto][port]['extrainfo']))
					print('CPE: %s' % (scanner[host][proto][port]['cpe']))


class Intensitysix(Scanning):
	def results(self):
		print("test Six")
		#		scan the ip range and ports
		scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 6')
#		set the scan to return the host
		hostRange = scanner.all_hosts()
		for host in hostRange:
			print('Target: %s (%s)' % (host, scanner[host].hostname()))
#            #return the information by port
			for proto in scanner[host].all_protocols():
				print('Protocol: %s' % proto)
				scannedBanner = scanner[host][proto].keys()
				for port in scannedBanner:
					print('Port: %s' % (port))
					print('State|Reason: %s|%s' % (scanner[host][proto][port]['state'],scanner[host][proto][port]['reason']))
					print('Name: %s' % (scanner[host][proto][port]['name']))
					print('Product|Version: %s|%s' % (scanner[host][proto][port]['product'],scanner[host][proto][port]['version']))
					print('Extra Information: %s' % (scanner[host][proto][port]['extrainfo']))
					print('CPE: %s' % (scanner[host][proto][port]['cpe']))


class Intensityseven(Scanning):
	def results(self):
		print("test Seven")
		#		scan the ip range and ports
		scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 7')
#		set the scan to return the host
		hostRange = scanner.all_hosts()
		for host in hostRange:
			print('Target: %s (%s)' % (host, scanner[host].hostname()))
#            #return the information by port
			for proto in scanner[host].all_protocols():
				print('Protocol: %s' % proto)
				scannedBanner = scanner[host][proto].keys()
				for port in scannedBanner:
					print('Port: %s' % (port))
					print('State|Reason: %s|%s' % (scanner[host][proto][port]['state'],scanner[host][proto][port]['reason']))
					print('Name: %s' % (scanner[host][proto][port]['name']))
					print('Product|Version: %s|%s' % (scanner[host][proto][port]['product'],scanner[host][proto][port]['version']))
					print('Extra Information: %s' % (scanner[host][proto][port]['extrainfo']))
					print('CPE: %s' % (scanner[host][proto][port]['cpe']))


class Intensityeight(Scanning):
	def results(self):
		print("test Eight")
		#		scan the ip range and ports
		scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 8')
#		set the scan to return the host
		hostRange = scanner.all_hosts()
		for host in hostRange:
			print('Target: %s (%s)' % (host, scanner[host].hostname()))
#            #return the information by port
			for proto in scanner[host].all_protocols():
				print('Protocol: %s' % proto)
				scannedBanner = scanner[host][proto].keys()
				for port in scannedBanner:
					print('Port: %s' % (port))
					print('State|Reason: %s|%s' % (scanner[host][proto][port]['state'],scanner[host][proto][port]['reason']))
					print('Name: %s' % (scanner[host][proto][port]['name']))
					print('Product|Version: %s|%s' % (scanner[host][proto][port]['product'],scanner[host][proto][port]['version']))
					print('Extra Information: %s' % (scanner[host][proto][port]['extrainfo']))
					print('CPE: %s' % (scanner[host][proto][port]['cpe']))


class Intensitynine(Scanning):
	def results(self):
		print("test nine")
		#		scan the ip range and ports
		test_scan = scanner.scan(self.ipaddress, self.ports, arguments='-sV --version-intensity 9')
		print(test_scan)
#		set the scan to return the host
#		hostRange = scanner.all_hosts()
#		for host in hostRange:
#			print('Target: %s (%s)' % (host, scanner[host].hostname()))
##            #return the information by port
#			for proto in scanner[host].all_protocols():
#				print('Protocol: %s' % proto)
#				scannedBanner = scanner[host][proto].keys()
#				for port in scannedBanner:
#					print('Port: %s' % (port))
#					print('State|Reason: %s|%s' % (scanner[host][proto][port]['state'],scanner[host][proto][port]['reason']))
#					print('Name: %s' % (scanner[host][proto][port]['name']))
#					print('Product|Version: %s|%s' % (scanner[host][proto][port]['product'],scanner[host][proto][port]['version']))
#					print('Extra Information: %s' % (scanner[host][proto][port]['extrainfo']))
#					print('CPE: %s' % (scanner[host][proto][port]['cpe']))
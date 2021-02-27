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

class Httpauthfinder(Scanning):
	def results(self):
#		print ("Test http auth finder")
		test_scan = scanner.scan(self.ipaddress, self.ports, arguments="--script=http-auth-finder.nse")
#		print(test_scan)
		host_range = scanner.all_hosts()
		for host in host_range:
			print('Target: %s (%s)' % (host, scanner[host].hostname()))
			for proto in scanner[host].all_protocols():
				scannedBanner = scanner[host][proto].keys()
				for port in scannedBanner:
					print('Pages that require Forms: %s' % (scanner[host][proto][port]['script']))
			


class Httpauth(Scanning):
	def results(self):
		print ("Test http auth")
		test_scan = scanner.scan(self.ipaddress, self.ports, arguments="--script=http-auth.nse")
		print(test_scan)


class Httpenum(Scanning):
	def results(self):
		print ("Test http enum")
		test_scan = scanner.scan(self.ipaddress, self.ports, arguments="--script=http-enum.nse")
#		print(test_scan)
		host_range = scanner.all_hosts()
		for host in host_range:
			print('Target: %s (%s)' % (host, scanner[host].hostname()))
			for proto in scanner[host].all_protocols():
				scannedBanner = scanner[host][proto].keys()
				for port in scannedBanner:
					print('Pages that require Forms: %s' % (scanner[host][proto][port]['script']))


class Httpmethods(Scanning):
	def results(self):
#		print ("Test http methods")
		test_scan = scanner.scan(self.ipaddress, self.ports, arguments="--script=http-methods.nse")
#		print(test_scan)
		host_range = scanner.all_hosts()
		for host in host_range:
			print('Target: %s (%s)' % (host, scanner[host].hostname()))
			for proto in scanner[host].all_protocols():
				scannedBanner = scanner[host][proto].keys()
				for port in scannedBanner:
					print('Pages that require Forms: %s' % (scanner[host][proto][port]['script']))


class Httpwaf(Scanning):
	def results(self):
		print ("Test http waf")
		test_scan = scanner.scan(self.ipaddress, self.ports, arguments="--script=http-waf-fingerprint.nse")
		print(test_scan)
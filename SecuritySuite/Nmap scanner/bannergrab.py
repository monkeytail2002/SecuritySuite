#!/usr/bin/env python

#import required modules
import nmap
#Set the scanner for the nmap module
scanner = nmap.PortScanner()

#parent class that contains the instantiation module
class Scanning:
	def __init__(self,ipaddress,ports):
		self.ipaddress = ipaddress
		self.ports = ports


#Class for grabbing banners (meta information about networks and servers for opsec
class Bannergrab(Scanning):
	def results(self):
		#scan the ip range, port range and insert the banner script along with the -sV option
		scanner.scan(self.ipaddress, self.ports,arguments='-sV -script=banner')
		#set the scan to return the host
		hostRange = scanner.all_hosts()
		for host in hostRange:
			print('Target: %s (%s)' % (host, scanner[host].hostname()))
			#return the information from the banner
			scannedBanner = scanner[host].all_protocols()
			for proto in scannedBanner:
				meh = scanner[host][proto].keys()
				print('Protocol: %s Software: %s Version: %s' % (scanner[host][proto][80]['name'],scanner[host][proto][80]['product'],scanner[host][proto][80]['version']))
				print('Banner %s' % (scanner[host][proto][80]['script']))
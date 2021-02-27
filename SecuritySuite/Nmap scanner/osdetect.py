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


class Limitedos(Scanning):
	def results(self):
#		print("limited")
		test_scan = scanner.scan(self.ipaddress, arguments='-O -v --osscan-limit')
		print('Hosts Up | Down: %s | %s' % (test_scan["nmap"]["scanstats"]["uphosts"], test_scan["nmap"]["scanstats"]["downhosts"]))
		print('Total Hosts Scanned: %s' % (test_scan["nmap"]["scanstats"]["totalhosts"]))
		hostRange = scanner.all_hosts()
		for host in hostRange:
			print('Target: %s (%s)' % (host, scanner[host].hostname()))
			print('State: %s' % (scanner[host]["status"]["state"]))
			print('Uptime Seconds | Last Boot: %s | %s' % (scanner[host]["uptime"]["seconds"], scanner[host]["uptime"]["lastboot"]))
			detected_os = scanner[host]["osmatch"]
			for os in detected_os:
				print('OS Type: %s' % (os["name"]))
				print('Accuracy: %s' % (os["accuracy"]))
				os_info = os["osclass"]
				for info in os_info:
					print('Type: %s' % (info["type"]))
					print('Vendor: %s' % (info["vendor"]))
					print('OS Family: %s' % (info["osfamily"]))
					print('Kernel Version: %s' % (info["osgen"]))
					print('Accuracy Rating: %s' % (info["accuracy"]))
					print('Extra Information: %s' % (info['cpe']))



class Guessos(Scanning):
	def results(self):
#		print("Guess")
		test_scan = scanner.scan(self.ipaddress, arguments='-O -v --osscan-guess')
		print('Hosts Up | Down: %s | %s' % (test_scan["nmap"]["scanstats"]["uphosts"], test_scan["nmap"]["scanstats"]["downhosts"]))
		print('Total Hosts Scanned: %s' % (test_scan["nmap"]["scanstats"]["totalhosts"]))
		hostRange = scanner.all_hosts()
		for host in hostRange:
			print('Target: %s (%s)' % (host, scanner[host].hostname()))
			print('State: %s' % (scanner[host]["status"]["state"]))
			print('Uptime Seconds | Last Boot: %s | %s' % (scanner[host]["uptime"]["seconds"], scanner[host]["uptime"]["lastboot"]))
			detected_os = scanner[host]["osmatch"]
			for os in detected_os:
				print('OS Type: %s' % (os["name"]))
				print('Accuracy: %s' % (os["accuracy"]))
				os_info = os["osclass"]
				for info in os_info:
					print('Type: %s' % (info["type"]))
					print('Vendor: %s' % (info["vendor"]))
					print('OS Family: %s' % (info["osfamily"]))
					print('Kernel Version: %s' % (info["osgen"]))
					print('Accuracy Rating: %s' % (info["accuracy"]))
					print('Extra Information: %s' % (info['cpe']))

class Maxoneos(Scanning):
	def results(scan):
#		print("Max one")
		test_scan = scanner.scan(self.ipaddress, arguments='-O -v --max-os-tries 1')
		print('Hosts Up | Down: %s | %s' % (test_scan["nmap"]["scanstats"]["uphosts"], test_scan["nmap"]["scanstats"]["downhosts"]))
		print('Total Hosts Scanned: %s' % (test_scan["nmap"]["scanstats"]["totalhosts"]))
		hostRange = scanner.all_hosts()
		for host in hostRange:
			print('Target: %s (%s)' % (host, scanner[host].hostname()))
			print('State: %s' % (scanner[host]["status"]["state"]))
			print('Uptime Seconds | Last Boot: %s | %s' % (scanner[host]["uptime"]["seconds"], scanner[host]["uptime"]["lastboot"]))
			detected_os = scanner[host]["osmatch"]
			for os in detected_os:
				print('OS Type: %s' % (os["name"]))
				print('Accuracy: %s' % (os["accuracy"]))
				os_info = os["osclass"]
				for info in os_info:
					print('Type: %s' % (info["type"]))
					print('Vendor: %s' % (info["vendor"]))
					print('OS Family: %s' % (info["osfamily"]))
					print('Kernel Version: %s' % (info["osgen"]))
					print('Accuracy Rating: %s' % (info["accuracy"]))
					print('Extra Information: %s' % (info['cpe']))


class Maxtwoos(Scanning):
	def results(scan):
#		print("Max two")
		test_scan = scanner.scan(self.ipaddress, arguments='-O -v --max-os-tries 2')
		print('Hosts Up | Down: %s | %s' % (test_scan["nmap"]["scanstats"]["uphosts"], test_scan["nmap"]["scanstats"]["downhosts"]))
		print('Total Hosts Scanned: %s' % (test_scan["nmap"]["scanstats"]["totalhosts"]))
		hostRange = scanner.all_hosts()
		for host in hostRange:
			print('Target: %s (%s)' % (host, scanner[host].hostname()))
			print('State: %s' % (scanner[host]["status"]["state"]))
			print('Uptime Seconds | Last Boot: %s | %s' % (scanner[host]["uptime"]["seconds"], scanner[host]["uptime"]["lastboot"]))
			detected_os = scanner[host]["osmatch"]
			for os in detected_os:
				print('OS Type: %s' % (os["name"]))
				print('Accuracy: %s' % (os["accuracy"]))
				os_info = os["osclass"]
				for info in os_info:
					print('Type: %s' % (info["type"]))
					print('Vendor: %s' % (info["vendor"]))
					print('OS Family: %s' % (info["osfamily"]))
					print('Kernel Version: %s' % (info["osgen"]))
					print('Accuracy Rating: %s' % (info["accuracy"]))
					print('Extra Information: %s' % (info['cpe']))


class Maxthreeos(Scanning):
	def results(scan):
#		print("Max three")
		test_scan = scanner.scan(self.ipaddress, arguments='-O -v --max-os-tries 3')
		print('Hosts Up | Down: %s | %s' % (test_scan["nmap"]["scanstats"]["uphosts"], test_scan["nmap"]["scanstats"]["downhosts"]))
		print('Total Hosts Scanned: %s' % (test_scan["nmap"]["scanstats"]["totalhosts"]))
		hostRange = scanner.all_hosts()
		for host in hostRange:
			print('Target: %s (%s)' % (host, scanner[host].hostname()))
			print('State: %s' % (scanner[host]["status"]["state"]))
			print('Uptime Seconds | Last Boot: %s | %s' % (scanner[host]["uptime"]["seconds"], scanner[host]["uptime"]["lastboot"]))
			detected_os = scanner[host]["osmatch"]
			for os in detected_os:
				print('OS Type: %s' % (os["name"]))
				print('Accuracy: %s' % (os["accuracy"]))
				os_info = os["osclass"]
				for info in os_info:
					print('Type: %s' % (info["type"]))
					print('Vendor: %s' % (info["vendor"]))
					print('OS Family: %s' % (info["osfamily"]))
					print('Kernel Version: %s' % (info["osgen"]))
					print('Accuracy Rating: %s' % (info["accuracy"]))
					print('Extra Information: %s' % (info['cpe']))


class Maxfouros(Scanning):
	def results(scan):
#		print("Max four")
		test_scan = scanner.scan(self.ipaddress, arguments='-O -v --max-os-tries 4')
		print('Hosts Up | Down: %s | %s' % (test_scan["nmap"]["scanstats"]["uphosts"], test_scan["nmap"]["scanstats"]["downhosts"]))
		print('Total Hosts Scanned: %s' % (test_scan["nmap"]["scanstats"]["totalhosts"]))
		hostRange = scanner.all_hosts()
		for host in hostRange:
			print('Target: %s (%s)' % (host, scanner[host].hostname()))
			print('State: %s' % (scanner[host]["status"]["state"]))
			print('Uptime Seconds | Last Boot: %s | %s' % (scanner[host]["uptime"]["seconds"], scanner[host]["uptime"]["lastboot"]))
			detected_os = scanner[host]["osmatch"]
			for os in detected_os:
				print('OS Type: %s' % (os["name"]))
				print('Accuracy: %s' % (os["accuracy"]))
				os_info = os["osclass"]
				for info in os_info:
					print('Type: %s' % (info["type"]))
					print('Vendor: %s' % (info["vendor"]))
					print('OS Family: %s' % (info["osfamily"]))
					print('Kernel Version: %s' % (info["osgen"]))
					print('Accuracy Rating: %s' % (info["accuracy"]))
					print('Extra Information: %s' % (info['cpe']))


class Maxfiveos(Scanning):
	def results(scan):
#		print("Max five")
		test_scan = scanner.scan(self.ipaddress, arguments='-O -v --max-os-tries 5')
		print('Hosts Up | Down: %s | %s' % (test_scan["nmap"]["scanstats"]["uphosts"], test_scan["nmap"]["scanstats"]["downhosts"]))
		print('Total Hosts Scanned: %s' % (test_scan["nmap"]["scanstats"]["totalhosts"]))
		hostRange = scanner.all_hosts()
		for host in hostRange:
			print('Target: %s (%s)' % (host, scanner[host].hostname()))
			print('State: %s' % (scanner[host]["status"]["state"]))
			print('Uptime Seconds | Last Boot: %s | %s' % (scanner[host]["uptime"]["seconds"], scanner[host]["uptime"]["lastboot"]))
			detected_os = scanner[host]["osmatch"]
			for os in detected_os:
				print('OS Type: %s' % (os["name"]))
				print('Accuracy: %s' % (os["accuracy"]))
				os_info = os["osclass"]
				for info in os_info:
					print('Type: %s' % (info["type"]))
					print('Vendor: %s' % (info["vendor"]))
					print('OS Family: %s' % (info["osfamily"]))
					print('Kernel Version: %s' % (info["osgen"]))
					print('Accuracy Rating: %s' % (info["accuracy"]))
					print('Extra Information: %s' % (info['cpe']))
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


class Limitedos(Scanning):
	def limited_results(self):
#		print("limited")
		limited_scan = scanner.scan(self.ipaddress, arguments='-O -v --osscan-limit')
#		print(limited_scan)
		returned_list=[]
		returned_list.append(limited_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(limited_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(limited_scan["nmap"]["scanstats"]["totalhosts"])
		hostRange = scanner.all_hosts()
		for host in hostRange:
			returned_list.append(host)
			returned_list.append(scanner[host].hostname())
			returned_list.append(scanner[host]["status"]["state"])
			returned_list.append(scanner[host]["uptime"]["seconds"])
			returned_list.append(scanner[host]["uptime"]["lastboot"])			
			detected_os = scanner[host]["osmatch"]
			for os in detected_os:
				returned_list.append(os["name"])
				returned_list.append(os["accuracy"])
				os_info = os["osclass"]
				for info in os_info:
					returned_list.append(info["type"])
					returned_list.append(info["vendor"])
					returned_list.append(info["osfamily"])
					returned_list.append(info["osgen"])
					returned_list.append(info["accuracy"])
					returned_list.append(info["cpe"])
				print(returned_list)



class Guessos(Scanning):
	def guess_results(self):
#		print("Guess")
		guess_scan = scanner.scan(self.ipaddress, arguments='-O -v --osscan-limit')
#		print(guess_scan)
		returned_list=[]
		returned_list.append(guess_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(guess_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(guess_scan["nmap"]["scanstats"]["totalhosts"])
		hostRange = scanner.all_hosts()
		for host in hostRange:
			returned_list.append(host)
			returned_list.append(scanner[host].hostname())
			returned_list.append(scanner[host]["status"]["state"])
			returned_list.append(scanner[host]["uptime"]["seconds"])
			returned_list.append(scanner[host]["uptime"]["lastboot"])			
			detected_os = scanner[host]["osmatch"]
			for os in detected_os:
				returned_list.append(os["name"])
				returned_list.append(os["accuracy"])
				os_info = os["osclass"]
				for info in os_info:
					returned_list.append(info["type"])
					returned_list.append(info["vendor"])
					returned_list.append(info["osfamily"])
					returned_list.append(info["osgen"])
					returned_list.append(info["accuracy"])
					returned_list.append(info["cpe"])
				print(returned_list)

class Maxoneos(Scanning):
	def maxone_results(self):
#		print("Max one")
		maxone_scan = scanner.scan(self.ipaddress, arguments='-O -v --osscan-limit')
#		print(maxone_scan)
		returned_list=[]
		returned_list.append(maxone_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(maxone_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(maxone_scan["nmap"]["scanstats"]["totalhosts"])
		hostRange = scanner.all_hosts()
		for host in hostRange:
			returned_list.append(host)
			returned_list.append(scanner[host].hostname())
			returned_list.append(scanner[host]["status"]["state"])
			returned_list.append(scanner[host]["uptime"]["seconds"])
			returned_list.append(scanner[host]["uptime"]["lastboot"])			
			detected_os = scanner[host]["osmatch"]
			for os in detected_os:
				returned_list.append(os["name"])
				returned_list.append(os["accuracy"])
				os_info = os["osclass"]
				for info in os_info:
					returned_list.append(info["type"])
					returned_list.append(info["vendor"])
					returned_list.append(info["osfamily"])
					returned_list.append(info["osgen"])
					returned_list.append(info["accuracy"])
					returned_list.append(info["cpe"])
				print(returned_list)


class Maxtwoos(Scanning):
	def maxtwo_results(self):
#		print("Max two")
		maxtwo_scan = scanner.scan(self.ipaddress, arguments='-O -v --osscan-limit')
#		print(maxtwo_scan)
		returned_list=[]
		returned_list.append(maxtwo_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(maxtwo_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(maxtwo_scan["nmap"]["scanstats"]["totalhosts"])
		hostRange = scanner.all_hosts()
		for host in hostRange:
			returned_list.append(host)
			returned_list.append(scanner[host].hostname())
			returned_list.append(scanner[host]["status"]["state"])
			returned_list.append(scanner[host]["uptime"]["seconds"])
			returned_list.append(scanner[host]["uptime"]["lastboot"])			
			detected_os = scanner[host]["osmatch"]
			for os in detected_os:
				returned_list.append(os["name"])
				returned_list.append(os["accuracy"])
				os_info = os["osclass"]
				for info in os_info:
					returned_list.append(info["type"])
					returned_list.append(info["vendor"])
					returned_list.append(info["osfamily"])
					returned_list.append(info["osgen"])
					returned_list.append(info["accuracy"])
					returned_list.append(info["cpe"])
				print(returned_list)


class Maxthreeos(Scanning):
	def maxthree_results(self):
#		print("Max three")
		maxthree_scan = scanner.scan(self.ipaddress, arguments='-O -v --osscan-limit')
#		print(maxthree_scan)
		returned_list=[]
		returned_list.append(maxthree_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(maxthree_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(maxthree_scan["nmap"]["scanstats"]["totalhosts"])
		hostRange = scanner.all_hosts()
		for host in hostRange:
			returned_list.append(host)
			returned_list.append(scanner[host].hostname())
			returned_list.append(scanner[host]["status"]["state"])
			returned_list.append(scanner[host]["uptime"]["seconds"])
			returned_list.append(scanner[host]["uptime"]["lastboot"])			
			detected_os = scanner[host]["osmatch"]
			for os in detected_os:
				returned_list.append(os["name"])
				returned_list.append(os["accuracy"])
				os_info = os["osclass"]
				for info in os_info:
					returned_list.append(info["type"])
					returned_list.append(info["vendor"])
					returned_list.append(info["osfamily"])
					returned_list.append(info["osgen"])
					returned_list.append(info["accuracy"])
					returned_list.append(info["cpe"])
				print(returned_list)


class Maxfouros(Scanning):
	def maxfour_results(self):
#		print("Max four")
		maxfour_scan = scanner.scan(self.ipaddress, arguments='-O -v --osscan-limit')
#		print(maxfour_scan)
		returned_list=[]
		returned_list.append(maxfour_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(maxfour_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(maxfour_scan["nmap"]["scanstats"]["totalhosts"])
		hostRange = scanner.all_hosts()
		for host in hostRange:
			returned_list.append(host)
			returned_list.append(scanner[host].hostname())
			returned_list.append(scanner[host]["status"]["state"])
			returned_list.append(scanner[host]["uptime"]["seconds"])
			returned_list.append(scanner[host]["uptime"]["lastboot"])			
			detected_os = scanner[host]["osmatch"]
			for os in detected_os:
				returned_list.append(os["name"])
				returned_list.append(os["accuracy"])
				os_info = os["osclass"]
				for info in os_info:
					returned_list.append(info["type"])
					returned_list.append(info["vendor"])
					returned_list.append(info["osfamily"])
					returned_list.append(info["osgen"])
					returned_list.append(info["accuracy"])
					returned_list.append(info["cpe"])
				print(returned_list)


class Maxfiveos(Scanning):
	def maxfive_results(self):
#		print("Max five")
		maxfive_scan = scanner.scan(self.ipaddress, arguments='-O -v --osscan-limit')
#		print(maxfive_scan)
		returned_list=[]
		returned_list.append(maxfive_scan["nmap"]["scanstats"]["uphosts"])
		returned_list.append(maxfive_scan["nmap"]["scanstats"]["downhosts"])
		returned_list.append(maxfive_scan["nmap"]["scanstats"]["totalhosts"])
		hostRange = scanner.all_hosts()
		for host in hostRange:
			returned_list.append(host)
			returned_list.append(scanner[host].hostname())
			returned_list.append(scanner[host]["status"]["state"])
			returned_list.append(scanner[host]["uptime"]["seconds"])
			returned_list.append(scanner[host]["uptime"]["lastboot"])			
			detected_os = scanner[host]["osmatch"]
			for os in detected_os:
				returned_list.append(os["name"])
				returned_list.append(os["accuracy"])
				os_info = os["osclass"]
				for info in os_info:
					returned_list.append(info["type"])
					returned_list.append(info["vendor"])
					returned_list.append(info["osfamily"])
					returned_list.append(info["osgen"])
					returned_list.append(info["accuracy"])
					returned_list.append(info["cpe"])
				print(returned_list)
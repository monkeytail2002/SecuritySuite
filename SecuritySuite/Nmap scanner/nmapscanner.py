#import the module for nmap
import nmap

#set up the nmap command for port scanning
nmScan = nmap.PortScanner()

#parent class that contains the instantiation module
class Scanning:
	def __init__(self,ipaddress,ports):
		self.ipaddress = ipaddress
		self.ports = ports

#child class for open port scanning
class Portscan(Scanning):
	def results(self):
		#scan the ip and port range
		nmScan.scan(self.ipaddress, self.ports)
		#put all scanned hosts to a variable
		hostRange = nmScan.all_hosts()
		#run for loop for hosts in range
		for host in hostRange:
			print('Host : %s (%s)' % (host, nmScan[host].hostname()))
			#run for loop for all protocols returned
			for proto in nmScan[host].all_protocols():
				print('Protocol : %s' % proto)
				#put returned ports into keys
				scannedPorts = nmScan[host][proto].keys()
				#run for loop for returned ports
				for port in scannedPorts:
					print('port: %s\tstate: %s' % (port, nmScan[host][proto][port]['state']))

#Class for grabbing banners (meta information about networks and servers for opsec
class Bannergrab(Scanning):
	def results(self):
		#scan the ip range, port range and insert the banner script along with the -sV option
		nmScan.scan(self.ipaddress, self.ports,arguments='-sV -script=banner')
		#set the scan to return the host
		hostRange = nmScan.all_hosts()
		for host in hostRange:
			print('Target: %s (%s)' % (host, nmScan[host].hostname()))
			#return the information from the banner
			scannedBanner = nmScan[host].all_protocols()
			for proto in scannedBanner:
				meh = nmScan[host][proto].keys()
				print('Protocol: %s Software: %s Version: %s' % (nmScan[host][proto][80]['name'],nmScan[host][proto][80]['product'],nmScan[host][proto][80]['version']))
				print('Banner %s' % (nmScan[host][proto][80]['script']))


#input the test ip address and port range using user input
userIP = input("Please enter your IP range:\n")
userPort = input("Please enter your port range:\n")
#testing = Portscan(userIP,userPort)
testBanner = Bannergrab(userIP,userPort)
#run the port scan
#testing.results()
testBanner.results()

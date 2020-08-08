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


#input the test ip address and port range
testing = Portscan('127.0.0.1','21-443')
#run the port scan
testing.results()

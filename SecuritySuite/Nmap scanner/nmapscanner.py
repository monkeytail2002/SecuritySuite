#import the module for nmap
import nmap

#set up the nmap command for port scanning
nmScan = nmap.PortScanner()

#parent class that instantiates the ip address and ports
class Scanning:
	def __init__(self,ipaddress,ports):
		self.ipaddress = ipaddress
		self.ports = ports

#Child class of Scanning.  Runs the port scan and returns results.
class Portscan(Scanning):
	def results(self):
		test = nmScan.scan(self.ipaddress)
		print(test)

#input the test ip address and port range.
p = Portscan('127.0.0.1','21-443')
#run the port scan.
p.results()
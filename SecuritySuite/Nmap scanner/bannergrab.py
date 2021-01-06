class Bannergrab(Scanning):
	def results(self):
		#scan the ip range, port range and insert the banner script along with the -sV option
		scanner.scan(self.ipaddress, self.ports,arguments='-sV -script=banner')
		#set the scan to return the host
		hostRange = scanner.all_hosts()
        for host in hostRange:
			print('Target: %s (%s)' % (host, scanner[host].hostname()))
            #return the information from the banner by port
            for proto in scanner[host].all_protocols():
                print('Protocol: %s' % proto)
                scannedBanner = scanner[host][proto].keys()
                for port in scannedBanner:
                    print('Port: %s' % (port))
                    print('State|Reason: %s|%s' % (scanner[host][proto][port]['state'],scanner[host][proto][port]['reason']))
                    print('Name: %s' % (scanner[host][proto][port]['name']))
                    print('Product|Version: %|%s' % (scanner[host][proto][port]['product'],scanner[host][proto][port]['version']))
                    print('Extra Information: %s' % (scanner[host][proto][port]['extrainfo']))
                    print('CPE: %s' % (scanner[host][proto][port]['cpe']))
                    print('Banner %s' % (scanner[host][proto][port]['script']))

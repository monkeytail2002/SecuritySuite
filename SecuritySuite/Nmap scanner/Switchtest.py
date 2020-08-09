#!/usr/bin/env python

import nmap
import portscan


userIP = "127.0.0.1"
userPort = "80"
userScan = input("Choose scan type\n"
                 "1. Default TCP scan\n"
                 "2. TCP SYN scan - Use this for stealthy scans.\n"
                 "3. UDP scan.\n"
                 "4. SCTP scan - Use this for Telecom networks.\n"
                 "5. Null scan - Use this for RST scanning.  Not suitable for Windows.\n"
                 "6. FIN scan - Use this for RST scanning.  Not suitable for Windows.\n"
                 "7. Xmas scan - Use this for RST scanning.  Not suitable for Windows.\n"
                 "8. TCP ACK scan.  Use this to determine firewall rules.\n"
                 "9. Advanced SCTP scan.\n"
                 "10. IP Protocol scan.\n" )



class Scanning:
    def __init__(self,ipaddress,ports):
        pass

userScan = int(userScan)
if userScan == 1:
    pscan = portscan.Portscan(userIP, userPort)
    pscan.results()
elif userScan == 2:
    pscan = portscan.Stealthscan(userIP, userPort)
    pscan.results()
elif userScan == 3:
    pscan = portscan.UDPScan(userIP, userPort)
    pscan.results()
elif userScan == 4:
    pscan = portscan.Sigtran(userIP, userPort)
    pscan.results()
elif userScan == 5:
    pscan = portscan.Nullscan(userIP, userPort)
    pscan.results()
elif userScan == 6:
    pscan = portscan.Finnscan(userIP, userPort)
    pscan.results()
elif userScan == 7:
    pscan = portscan.Xmasscan(userIP, userPort)
    pscan.results()
elif userScan == 8:
    pscan = portscan.TCPAckscan(userIP, userPort)
    pscan.results()
elif userScan == 9:
    pscan = portscan.Cookiescan(userIP, userPort)
    pscan.results()
elif userScan == 10:
    pscan = portscan.IPscan(userIP, userPort)
    pscan.results()
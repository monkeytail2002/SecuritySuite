#!/usr/bin/env python

import nmap
import portscan


userIP = "127.0.0.1"
userPort = "80"
userScan = input("Choose scan type\n")



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
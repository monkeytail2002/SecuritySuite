#!/usr/bin/env python3

import nmap
import sys

#Import modules for various scans
import portscan
import bannergrab
import versiondetect
import osdetect
import nsescripts

#Take in arguments from website
user_input = sys.argv[1]

user_list = user_input.split("~")

ip_range = user_list[0]
port_range = user_list[1]
use_test = user_list[2]
scan_type = int(use_test)

#print("Scan")
class Scanning:
	def __init__(self, ipaddress, ports):
		pass
	
if scan_type == 1:
    pscan = portscan.Portscan(ip_range, port_range)
    pscan.tcp_results()
elif scan_type == 2:
    pscan = portscan.Stealthscan(ip_range, port_range)
    pscan.stealth_result()
elif scan_type == 3:
    pscan = portscan.UDPScan(ip_range, port_range)
    pscan.udp_results()
elif scan_type == 4:
    pscan = portscan.Sigtran(ip_range, port_range)
    pscan.sigtran_results()
elif scan_type == 5:
    pscan = portscan.Nullscan(ip_range, port_range)
    pscan.null_results()
elif scan_type == 6:
    pscan = portscan.Finnscan(ip_range, port_range)
    pscan.finn_results()
elif scan_type == 7:
    pscan = portscan.Xmasscan(ip_range, port_range)
    pscan.xmas_results()
elif scan_type == 8:
    pscan = portscan.TCPAckscan(ip_range, port_range)
    pscan.tcpackscan_results()
elif scan_type == 9:
    pscan = portscan.Cookiescan(ip_range, port_range)
    pscan.cookie_results()
elif scan_type == 10:
    pscan = portscan.IPscan(ip_range, port_range)
    pscan.ipscan_results()
elif scan_type == 11:
	bgrab = bannergrab.Bannergrab(ip_range, port_range)
	bgrab.results()
elif scan_type == 12:
	bgrab = bannergrab.Bannervuln(ip_range, port_range)
	bgrab.vuln_results()
elif scan_type == 13:
	vdetect = versiondetect.Intensityzero(ip_range, port_range)
	vdetect.vzero_results()
elif scan_type == 14:
	vdetect = versiondetect.Intensityone(ip_range, port_range)
	vdetect.vone_results()
elif scan_type == 15:
	vdetect = versiondetect.Intensitytwo(ip_range, port_range)
	vdetect.vtwo_results()
elif scan_type == 16:
	vdetect = versiondetect.Intensitythree(ip_range, port_range)
	vdetect.vthree_results()
elif scan_type == 17:
	vdetect = versiondetect.Intensityfour(ip_range, port_range)
	vdetect.vfour_results()
elif scan_type == 18:
	vdetect = versiondetect.Intensityfive(ip_range, port_range)
	vdetect.vfive_results()
elif scan_type == 19:
	vdetect = versiondetect.Intensitysix(ip_range, port_range)
	vdetect.vsix_results()
elif scan_type == 20:
	vdetect = versiondetect.Intensityseven(ip_range, port_range)
	vdetect.vseven_results()
elif scan_type == 21:
	vdetect = versiondetect.Intensityeight(ip_range, port_range)
	vdetect.veight_results()
elif scan_type == 22:
	vdetect = versiondetect.Intensitynine(ip_range, port_range)
	vdetect.vnine_results()
elif scan_type == 23:
	odetect = osdetect.Limitedos(ip_range, port_range)
	odetect.limited_results()
elif scan_type == 24:
	odetect = osdetect.Guessos(ip_range, port_range)
	odetect.guess_results()
elif scan_type == 25:
	odetect = osdetect.Maxoneos(ip_range, port_range)
	odetect.maxone_results()
elif scan_type == 26:
	odetect = osdetect.Maxtwoos(ip_range, port_range)
	odetect.maxtwo_results()
elif scan_type == 27:
	odetect = osdetect.Maxthreeos(ip_range, port_range)
	odetect.maxthree_results()
elif scan_type == 28:
	odetect = osdetect.Maxfouros(ip_range, port_range)
	odetect.maxfour_results()
elif scan_type == 29:
	odetect = osdetect.Maxfiveos(ip_range, port_range)
	odetect.maxfive_results()
elif scan_type == 30:
	nsescript = nsescripts.Httpauthfinder(ip_range, port_range)
	nsescript.authfinder_results()
elif scan_type == 31:
	nsescript = nsescripts.Httpauth(ip_range, port_range)
	nsescript.httpauth_results()
elif scan_type == 32:
	nsescript = nsescripts.Httpenum(ip_range, port_range)
	nsescript.Httpenum_results()
elif scan_type == 33:
	nsescript = nsescripts.Httpmethods(ip_range, port_range)
	nsescript.Httpmethods_results()
elif scan_type == 34:
	nsescript = nsescripts.httpsitemapgenerator(ip_range, port_range)
	nsescript.sitemap_results()
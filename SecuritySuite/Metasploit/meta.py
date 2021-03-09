#!/usr/bin/env python

#Developed by Angus MacDonald(15009351) as part of the UG409758 Team Project module for BSc Computing Science.
#Tutor: Graeme Martindale
#Members of team: Angus MacDonald 15009351, Jordan L 15009237, Jim
#Version: 1.6 Date Completed and fully tested: 9/3/21

from pymetasploit3.msfrpc import MsfRpcClient
import sys
import configparser
import metainfo

#Read the config file for passwords
config=configparser.ConfigParser()
config.sections()
config.read('/home/leonardo/credentials.ini')


#pull in the password from the credentials file.
con_pass = config.get("keys",'metasploit_password')

#Test config pull
#print(con_pass)


#Take in user input and set it to a variable.
user_input = sys.argv[1]

user_list = user_input.split("~")

meta_module = user_list[0]
meta_group = user_list[1]


print(meta_module)
#Connect to Metasploit
meta_client = MsfRpcClient(con_pass)


#Set the user input to a wildcard search for the filter
search_pattern = meta_group+"*" 



class Scanning:
	def __init__(self, client, pattern):
		pass

	
if meta_module == "Exploits":
	meta_info = metainfo.Metainfo(meta_client, search_pattern)
	meta_info.exploit()
elif meta_module == "Auxiliaries":
	meta_info = metainfo.Metainfo(meta_client, search_pattern)
	meta_info.auxiliary()
elif meta_module == "Payloads":
	meta_info = metainfo.Metainfo(meta_client, search_pattern)
	meta_info.payload()
elif meta_module == "No Operations":
	meta_info = metainfo.Metainfo(meta_client, search_pattern)
	meta_info.nops()
elif meta_module == "Encoders":
	meta_info = metainfo.Metainfo(meta_client, search_pattern)
	meta_info.encoders()
elif meta_module == "Posts":
	meta_info = metainfo.Metainfo(meta_client, search_pattern)
	meta_info.posts()
	
		
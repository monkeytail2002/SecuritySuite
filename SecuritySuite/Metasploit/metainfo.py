#!/usr/bin/env python

#Developed by Angus MacDonald(15009351) as part of the UG409758 Team Project module for BSc Computing Science.
#Tutor: Graeme Martindale
#Members of team: Angus MacDonald 15009351, Jordan Laing 15009237, Jim Baird 10003644
#Version: 2.0 Date Completed and fully tested: 19/3/21

#Import required modules
import fnmatch
import json


#set the scanning class to take in the ipaddress and port from the nmapscan.py file
class Scanning:
	def __init__(self,client,pattern):
		self.client = client
		self.pattern = pattern

		
class Metainfo(Scanning):	
	def exploit(self):
		#Set the variables
		meta_client = self.client
		meta_pattern = self.pattern
		
#		Connect to the metasploit database
		exploit = meta_client.modules.exploits
#		Use the fnmatch module to filter the list for the user input and print it.
		filtered_exploit = fnmatch.filter(exploit, meta_pattern)
		#Set the lists
		returned_info=[]
		exploit_info=[]
		#Iterate through the filtered search and append returns to list
		for exploits in filtered_exploit:
			chosen_exploit = exploits
			#Set the information to a variable to that it can be used.
			exploit_information = meta_client.modules.use('exploit', chosen_exploit)
#			Set the lists
			author_list = []
			option_list = []
			require_list = []
			payload_list = []
#			Iterate through the returned lists and set them to keys so that they can be manipulated in php
			for authored in exploit_information.authors:
				author_list.append({'author':authored})
			for optioned in exploit_information.options:
				option_list.append({'option':optioned})
			for require in exploit_information.required:
				require_list.append({'required':require})
			for payload in exploit_information.payloads:
				payload_list.append({'payload':payload})
#			Append the lists into the exploit info list so that the information is kept to individual exploits
			exploit_info.append({'exploit': chosen_exploit, 'description': exploit_information.description, 'authors':author_list, 'options': option_list, 'required': require_list, 'payloads': payload_list})
		#append the information to the returned_info list
		returned_info.append(exploit_info)
		#Dump it into a json
		returned_exploit = json.dumps(returned_info)
		print(returned_exploit)
		
	
	def payload(self):
		#Set the variables
		meta_client = self.client
		meta_pattern = self.pattern
		#Connect to the database
		payload = meta_client.modules.payloads
		
#		Use the fnmatch module to filter the list for the user input and print it.
		filtered_payloads = fnmatch.filter(payload, meta_pattern)
		#Set the list
		returned_payload=[]
		payload_info = []
		#Iterate through the filtered search and append returns to list
		for payloads in filtered_payloads:
			chosen_payload = payloads
			#Load the payload from the database
			payload_information = meta_client.modules.use('payload', chosen_payload)
			#Create empty listss
			author_list = []
			option_list = []
			require_list = []
			#Iterate through the returned information
			for authored in payload_information.authors:
				author_list.append({'author':authored})
			for optioned in payload_information.options:
				option_list.append({'option':optioned})
			for require in payload_information.required:
				require_list.append({'required':require})
#			Append the lists into the exploit info list so that the information is kept to individual exploits
			payload_info.append({'payload': chosen_payload, 'description': payload_information.description, 'authors':author_list, 'options': option_list, 'required': require_list})
		
		#append the information to the returned_info list
		returned_payload.append(payload_info)
		
		#Dump it into a json
		returned_payload = json.dumps(returned_payload)
		print(returned_payload)
	
	def auxiliaries(self):
		#Set the variables
		meta_client = self.client
		meta_pattern = self.pattern
		#Connect to the database
		auxiliaries = meta_client.modules.auxiliary
		
#		Use the fnmatch module to filter the list for the user input and print it.
		filtered_auxiliaries = fnmatch.filter(auxiliaries, meta_pattern)
		#Set the list
		returned_auxiliaries=[]
		auxiliary_info = []
		#Iterate through the filtered search and append returns to list
		for auxiliaries in filtered_auxiliaries:
			chosen_auxiliary = auxiliaries
			#Load the payload from the database
			auxiliaries_information = meta_client.modules.use('auxiliary', chosen_auxiliary)
			#Create empty lists
			author_list = []
			option_list = []
			require_list = []
			#Iterate through the returned information
			for authored in auxiliaries_information.authors:
				author_list.append({'author':authored})
			for optioned in auxiliaries_information.options:
				option_list.append({'option':optioned})
			for require in auxiliaries_information.required:
				require_list.append({'required':require})
#			Append the lists into the exploit info list so that the information is kept to individual exploits
			auxiliary_info.append({'auxiliary': chosen_auxiliary, 'description': auxiliaries_information.description, 'authors':author_list, 'options': option_list, 'required': require_list})
		
		#append the information to the returned_info list
		returned_auxiliaries.append(auxiliary_info)
		
		#Dump it into a json
		returned_auxiliaries = json.dumps(returned_auxiliaries)
		print(returned_auxiliaries)
		
	def nops(self):
		#Set the variables
		meta_client = self.client
		meta_pattern = self.pattern
		#Connect to the database
		nops = meta_client.modules.nops
		
#		Use the fnmatch module to filter the list for the user input and print it.
		filtered_nops = fnmatch.filter(nops, meta_pattern)
		#Set the list
		returned_nops=[]
		nops_info = []
		#Iterate through the filtered search and append returns to list
		for nops in filtered_nops:
			chosen_nops = nops
			#Load the payload from the database
			nops_information = meta_client.modules.use('nop', chosen_nops)
			#Create empty lists
			author_list = []
			option_list = []
			#Iterate through the returned information
			for authored in nops_information.authors:
				author_list.append({'author':authored})
			for optioned in nops_information.options:
				option_list.append({'option':optioned})
#			Append the lists into the exploit info list so that the information is kept to individual exploits
			nops_info.append({'nops': chosen_nops, 'description': nops_information.description, 'authors':author_list, 'options':option_list})
		
		#append the information to the returned_info list
		returned_nops.append(nops_info)
		
		#Dump it into a json
		returned_nops = json.dumps(returned_nops)
		print(returned_nops)

	def encoders(self):
		#Set the variables
		meta_client = self.client
		meta_pattern = self.pattern
		#Connect to the database
		encoders = meta_client.modules.encoders
		
#		Use the fnmatch module to filter the list for the user input and print it.
		filtered_encoders = fnmatch.filter(encoders, meta_pattern)
		#Set the list
		returned_encoders=[]
		encoders_info = []
		#Iterate through the filtered search and append returns to list
		for encoders in filtered_encoders:
			chosen_encoders = encoders
			#Load the payload from the database
			encoders_information = meta_client.modules.use('encoder', chosen_encoders)
			#Create empty lists
			author_list = []
			option_list = []
			require_list = []
			#Iterate through the returned information
			for authored in encoders_information.authors:
				author_list.append({'author':authored})
			for optioned in encoders_information.options:
				option_list.append({'option':optioned})
#			Append the lists into the exploit info list so that the information is kept to individual exploits
			encoders_info.append({'encoders': chosen_encoders, 'description': encoders_information.description, 'authors':author_list, 'options':option_list})
		
		#append the information to the returned_info list
		returned_encoders.append(encoders_info)
		
		#Dump it into a json
		returned_encoders = json.dumps(returned_encoders)
		print(returned_encoders)
		
	def posts(self):
		#Set the variables
		meta_client = self.client
		meta_pattern = self.pattern
		#Connect to the database
		posts = meta_client.modules.post
		
#		Use the fnmatch module to filter the list for the user input and print it.
		filtered_posts = fnmatch.filter(posts, meta_pattern)
		#Set the list
		returned_posts=[]
		posts_info = []
		#Iterate through the filtered search and append returns to list
		for posts in filtered_posts:
			chosen_posts = posts
			#Load the payload from the database
			posts_information = meta_client.modules.use('post', chosen_posts)
			#Create empty lists
			author_list = []
			option_list = []
			require_list = []

			#Iterate through the returned information
			for authored in posts_information.authors:
				author_list.append({'author':authored})
			for optioned in posts_information.options:
				option_list.append({'option':optioned})
			for require in posts_information.required:
				require_list.append({'required':require})
#			Append the lists into the exploit info list so that the information is kept to individual exploits
			posts_info.append({'posts': chosen_posts, 'description': posts_information.description, 'authors':author_list, 'options':option_list, 'required':require_list})
		
		#append the information to the returned_info list
		returned_posts.append(posts_info)
		
		#Dump it into a json
		returned_posts = json.dumps(returned_posts)
		print(returned_posts)
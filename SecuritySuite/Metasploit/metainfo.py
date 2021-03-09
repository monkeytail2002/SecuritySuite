#!/usr/bin/env python

#Developed by Angus MacDonald(15009351) as part of the UG409758 Team Project module for BSc Computing Science.
#Tutor: Graeme Martindale
#Members of team: Angus MacDonald 15009351, Jordan L 15009237, Jim
#Version: 1.8 Date Completed and fully tested: 9/3/21

#Import required modules
import fnmatch



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
		exploit = meta_client.modules.exploits
#		Use the fnmatch module to filter the list for the user input and print it.
		filtered_exploit = fnmatch.filter(exploit, meta_pattern)
		#Set the list
		returned_info=[]
		#Iterate through the filtered search and append returns to list
		for x in filtered_exploit:
			chosen_exploit = x
			returned_info.append(chosen_exploit)
			##Show data on chosen exploit
			exploit_information = meta_client.modules.use('exploit', chosen_exploit)
			returned_info.append(exploit_information.description)
			returned_info.append(exploit_information.authors)
			returned_info.append(exploit_information.options)
			returned_info.append(exploit_information.required)
			returned_info.append(exploit_information.payloads)
		print(returned_info)
		
	def auxiliary(self):
		#Set the variables
		meta_client = self.client
		meta_pattern = self.pattern
		auxiliaries = meta_client.modules.auxiliary
#		Use the fnmatch module to filter the list for the user input and print it.
		filtered_auxiliaries = fnmatch.filter(auxiliaries, meta_pattern)
		#Set the list
		returned_info=[]
		#Iterate through the filtered search and append returns to list
		for x in filtered_auxiliaries:
			chosen_auxiliaries = x
			returned_info.append(chosen_auxiliaries)
			##Show data on chosen exploit
			auxiliary_information = meta_client.modules.use('auxiliary', chosen_auxiliaries)
			returned_info.append(auxiliary_information.description)
			returned_info.append(auxiliary_information.authors)
			returned_info.append(auxiliary_information.options)
			returned_info.append(auxiliary_information.required)
		print(returned_info)

		
	def payload(self):
		#Set the variables
		meta_client = self.client
		meta_pattern = self.pattern
		payloads = meta_client.modules.payloads
#		Use the fnmatch module to filter the list for the user input and print it.
		filtered_payloads = fnmatch.filter(payloads, meta_pattern)
		#Set the list
		returned_info=[]
		#Iterate through the filtered search and append returns to list
		for x in filtered_payloads:
			chosen_payloads = x
			returned_info.append(chosen_payloads)
			##Show data on chosen exploit
			payload_information = meta_client.modules.use('payloads', chosen_payload)
			returned_info.append(payload_information.description)
			returned_info.append(payload_information.authors)
			returned_info.append(payload_information.options)
			returned_info.append(payload_information.required)
		print(returned_info)

		
	def nops(self):
		#Set the variables
		meta_client = self.client
		meta_pattern = self.pattern
		nops = meta_client.modules.nops
#		Use the fnmatch module to filter the list for the user input and print it.
		filtered_nops = fnmatch.filter(nops, meta_pattern)
		#Set the list
		returned_info=[]
		#Iterate through the filtered search and append returns to list
		for x in filtered_nops:
			chosen_nops = x
			returned_info.append(chosen_nops)
			##Show data on chosen exploit
			nops_information = meta_client.modules.use('nops', chosen_nops)
			returned_info.append(nops_information.description)
			returned_info.append(nops_information.authors)
			returned_info.append(nops_information.options)
			returned_info.append(nops_information.required)
		print(returned_info)
		
		
	def encoders(self):
		#Set the variables
		meta_client = self.client
		meta_pattern = self.pattern
		encoders = meta_client.modules.encoders
#		Use the fnmatch module to filter the list for the user input and print it.
		filtered_encoders = fnmatch.filter(encoders, meta_pattern)
		#Set the list
		returned_info=[]
		#Iterate through the filtered search and append returns to list
		for x in filtered_encoders:
			chosen_encoders = x
			returned_info.append(chosen_encoders)
			##Show data on chosen exploit
			encoders_information = meta_client.modules.use('encoders', chosen_exploit)
			returned_info.append(encoders_information.description)
			returned_info.append(encoders_information.authors)
			returned_info.append(encoders_information.options)
			returned_info.append(encoders_information.required)
		print(returned_info)
		
		
	def post(self):
		#Set the variables
		meta_client = self.client
		meta_pattern = self.pattern
		post = meta_client.modules.post
#		Use the fnmatch module to filter the list for the user input and print it.
		filtered_post = fnmatch.filter(post, meta_pattern)
		#Set the list
		returned_info=[]
		#Iterate through the filtered search and append returns to list
		for x in filtered_post:
			chosen_post = x
			returned_info.append(chosen_post)
			##Show data on chosen exploit
			post_information = meta_client.modules.use('post', chosen_exploit)
			returned_info.append(post_information.description)
			returned_info.append(post_information.authors)
			returned_info.append(post_information.options)
			returned_info.append(post_information.required)
		print(returned_info)
		
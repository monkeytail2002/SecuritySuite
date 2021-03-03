#v1.0

from pymetasploit3.msfrpc import MsfRpcClient
import fnmatch
import sys
import configparser

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


#Connect to Metasploit
client = MsfRpcClient(con_pass)

#set the exploit module
exploit = client.modules.exploits


#Set the user input to a wildcard search for the filter
pattern = user_input+"*" 

#Test the pattern variable
#print(pattern)


#Use the fnmatch module to filter the list for the user input and print it.
#filtered_exploit = fnmatch.filter(exploit, pattern)
#print(filtered_exploit)


#Set the auxiliaty modules.
#auxiliaries = client.modules.auxiliary
#print(auxiliaries)


#shows the encoders available
#encoders = client.modules.encoders
#print(encoders)

#shows the nops available
#nops = client.modules.nops
#print(nops)

#shows the encoders available
#payloads = client.modules.payloads
#print(payloads)


#shows the posts available
#post = client.modules.payloads
#print(post)

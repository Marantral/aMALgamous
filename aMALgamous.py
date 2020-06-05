#! /usr/bin/env python3

import importlib
from importlib import util
import netifaces
import os

spec = importlib.util.find_spec('.subserv', package='lib')
m = spec.loader.load_module()

spec1 = importlib.util.find_spec('.mal', package='Mod.Malware')
mal = spec1.loader.load_module()

spec2 = importlib.util.find_spec('.shel', package='Mod.Shell')
shel = spec2.loader.load_module()

spec3 = importlib.util.find_spec('.web', package='Mod.Web')
web = spec3.loader.load_module()

ifs = netifaces.interfaces()
for link in ifs:
    addrs = netifaces.ifaddresses(link)
    pong = addrs[netifaces.AF_INET]
    ping = str(pong).strip('[]')
    pongdoc = open("./src/.if_" + link, "w")
    pongdoc.write(ping)
    pongdoc.close()
os.system("grep \"{'addr': \" ./src/ -r | cut -d \"'\" -f 1,4 | cut -d '_' -f 2 | sed -e \"s/:{'/: /\" | grep -v 'lo' >./src/.ip")

def main():
    global local_ip

    print(m.bcolors.BOLD + m.bcolors.BLUE + r"""

             __  __          _                                           
            |  \/  |   /\   | |                                          
        __ _| \  / |  /  \  | |     __ _  __ _ _ __ ___   ___  _   _ ___ 
       / _` | |\/| | / /\ \ | |    / _` |/ _` | '_ ` _ \ / _ \| | | / __|
      | (_| | |  | |/ ____ \| |___| (_| | (_| | | | | | | (_) | |_| \__ \
       \__,_|_|  |_/_/    \_\______\__, |\__,_|_| |_| |_|\___/ \__,_|___/
                                    __/ |                                
                                   |___/                                 

""" + m.bcolors.ENDC)
    print(m.bcolors.GREEN + """\
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

""" + m.bcolors.ENDC)
    print("""\
                   Thanks all that helped and to the tidepod.
                    NSTS Cyber Security Penetration Testers
                                 version0.3
""")

    if ( m.listener_ip == "127.0.0.1"):
        local_ip = m.get_local_ip(m.interface)
        wireless = m.get_local_ip(m.winterface)
        print("The eth0 interface has: {0} : as its address. The wlan0 interface has: {1} : as its address.\n".format(
            local_ip,
            wireless) + m.bcolors.ERROR + m.bcolors.BOLD + "If you do not input a listener address it will default to the eth0 interface address\n\n" + m.bcolors.ENDC)
        int = open('./src/.ip')

        print(m.bcolors.ERROR + m.bcolors.BOLD + m.bcolors.UNDERLINE +"\t\tFor your benifit, here is all the IPs on this box.\n" + m.bcolors.ENDC)
        for line in int:
            print(m.bcolors.GREEN + "\t\t(*)"+ m.bcolors.ENDC +" -- " + line )
        int.close()
        os.system("rm ./src/.ip")
        os.system("rm ./src/.if_*")
        m.listener_ip = input("\tEnter IP Address for the Listener:  ") or local_ip

        print("\n\tYOU HAVE SET THE LHOST TO:   %s " % m.listener_ip)

    while(1):
      print(m.bcolors.BLUE + "\t*******************************************************************" + m.bcolors.ENDC)
      print(m.bcolors.BOLD + m.bcolors.GREEN +"""
        *******************************************************************
          _   _   _   _     _   _   _   _  
         / \ / \ / \ / \   / \ / \ / \ / \ 
        ( M | a | i | n ) ( M | e | n | u )
         \_/ \_/ \_/ \_/   \_/ \_/ \_/ \_/ 
      """+ m.bcolors.ENDC)
      print("\t*******************************************************************")
      print("\t*******************************************************************")
      print("\t*******************************************************************")
      print("\t(1)\tMalware Creation =======(generates malware and bypasses)")
      print("\t(2)\tShell Cheat ============(gives you shells to put in)")
      print("\t(3)\tWeb Payload Help =======(gives you payload help w/web apps)")
#      print("\t(4)\tKerb & Sysvol ==========(not yet developed)")
      print("\t(9)\tYou don't want to do anything----------(DUMB)")
      print("\t*******************************************************************")

      options = input("\nPiCk y0u4 Po1$oN: ")

      if options == "1":
         mal.Malware()
      elif options == "2":
         shel.Shells()
      elif options == "3":
         web.Web()
 #     elif options == "4":
  #       print("Nothing Yet")
      elif options == "9":
          exit()
      else:
         input("BAHHHHH PICK SOMETHING!!!!!!...")

#call main() function
if __name__ == '__main__':
  main()


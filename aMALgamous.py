#! /usr/bin/env python3

import importlib
from importlib import util
import netifaces
import os

# Connection to the subserv.py which provides consistent services to aMALgamous.
spec = importlib.util.find_spec('.subserv', package='lib')
m = spec.loader.load_module()

# Connection to the malware creation submenu.
spec1 = importlib.util.find_spec('.mal', package='Mod.Malware')
mal = spec1.loader.load_module()

# Connection the shell cheat submenu.
spec2 = importlib.util.find_spec('.shel', package='Mod.Shell')
shel = spec2.loader.load_module()

# Connection the Web cheat submenu.
spec3 = importlib.util.find_spec('.web', package='Mod.Web')
web = spec3.loader.load_module()

# Connection the Web cheat submenu.
spec4 = importlib.util.find_spec('.ssshhh', package='Mod.SSSHHH')
sh = spec4.loader.load_module()

# Linking the interfaces and finding out system IPs
ifs = netifaces.interfaces()
for link in ifs:
    try:
        addrs = netifaces.ifaddresses(link)
        pong = addrs[netifaces.AF_INET]
        ping = str(pong).strip('[]')
        pongdoc = open("./src/.if_" + link, "w")
        pongdoc.write(ping)
        pongdoc.close()
    except:
        pass

os.system(
    "grep \"{'addr': \" ./src/ -r | cut -d \"'\" -f 1,4 | cut -d '_' -f 2 | sed -e \"s/:{'/: /\" | grep -v 'lo' "
    ">./src/.ip")


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
                     Abricto Security - abrictosecurity.com
                                 version 0.5
""")
    # Listing out IPs and requiring a choice for the listener which will be used through out the running of the program.
    if m.listener_ip == "127.0.0.1":
        local_ip = m.get_local_ip(m.interface)
        wireless = m.get_local_ip(m.winterface)
        print("The eth0 interface has: {0} : as its address. The wlan0 interface has: {1} : as its address.\n".format(
            local_ip,
            wireless) + m.bcolors.ERROR + m.bcolors.BOLD + "If you do not input a listener address it will default to "
                                                           "the eth0 interface address\n\n" + m.bcolors.ENDC)
        ips = open('./src/.ip')

        print(
            "\t\t" + m.bcolors.ERROR + m.bcolors.BOLD + m.bcolors.UNDERLINE + "For your benefit, here is all the IPs "
                                                                              "on this box.\n" + m.bcolors.ENDC)
        for line in ips:
            print(m.bcolors.GREEN + "\t\t(*)" + m.bcolors.ENDC + " -- " + line)
        ips.close()
        os.system("rm ./src/.ip")
        os.system("rm ./src/.if_*")
        while (1):
            m.listener_ip = input("\tEnter IP Address for the Listener:  ") or local_ip
            if m.listener_ip == "h":
                m.helpm()
            elif m.listener_ip == "H":
                m.helpm()
            elif m.listener_ip == "help":
                m.helpm()
            elif m.listener_ip == "Help":
                m.helpm()
            elif m.listener_ip == "HELP":
                m.helpm()
            else:
                break

        print("\n\tYOU HAVE SET THE LHOST TO:   %s " % m.listener_ip)
    # MAIN MENU
    while (1):
        print(m.bcolors.BLUE + "\t*******************************************************************" + m.bcolors.ENDC)
        print(m.bcolors.BOLD + m.bcolors.GREEN + """
        *******************************************************************
          _   _   _   _     _   _   _   _  
         / \ / \ / \ / \   / \ / \ / \ / \ 
        ( M | a | i | n ) ( M | e | n | u )
         \_/ \_/ \_/ \_/   \_/ \_/ \_/ \_/ 
      """ + m.bcolors.ENDC)
        print("\t*******************************************************************")
        print("\t*******************************************************************")
        print("\t*******************************************************************")
        print("\t(1)\tMalware Creation =======(generates malware and bypasses)")
        print("\t(2)\tShell Cheat ============(gives you shells to put in)")
        print("\t(3)\tWeb Payload Help =======(gives you payload help w/web apps)")
        print("\t(4)\tSSSHHH C2 ==========(Creates command and control through AWS S3 Buckets)")
        print("\t(9)\tYou don't want to do anything----------(DUMB)")
        print("\t*******************************************************************")

        options = input("\nPiCk y0u4 Po1$oN: ")

        if options == "1":
            mal.Malware()
        elif options == "2":
            shel.Shells()
        elif options == "3":
            web.Web()
        elif options == "4":
            sh.ssshhh()
        elif options == "9":
            exit()
        elif options == 'h':
            m.helpm()
        elif options == 'H':
            m.helpm()
        elif options == 'help':
            m.helpm()
        elif options == 'HELP':
            m.helpm()
        elif options == 'Help':
            m.helpm()
        else:
            input("BAHHHHH PICK SOMETHING!!!!!!... Press Enter to continue!")


# call main() function
if __name__ == '__main__':
    main()

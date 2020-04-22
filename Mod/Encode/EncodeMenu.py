#! /usr/bin/env python3

## Payload Encoding Submenu
import os
import importlib
from importlib import util

spec = importlib.util.find_spec('.subserv', package='lib')
m = spec.loader.load_module()

spec1 = importlib.util.find_spec('.xss', package='Mod.Web.XSS')
xss = spec1.loader.load_module()

spec2 = importlib.util.find_spec('.xxe', package='Mod.Web.XXE')
xxe = spec2.loader.load_module()

spec3 = importlib.util.find_spec('.ssti', package='Mod.Web.SSTI')
ssti = spec3.loader.load_module()

## Malware Sub-menu
def Web():
  os.system("clear")
  print(m.bcolors.GREEN + m.bcolors.BOLD + m.bcolors.UNDERLINE + "\tIt's WEB TIME!!!!!" + m.bcolors.ENDC)
  while(1):
    print(m.bcolors.BLUE + "\t*******************************************************************" + m.bcolors.ENDC)
    print(m.bcolors.BOLD + m.bcolors.BLUE +"""
        *******************************************************************
          _   _   _     _   _   _   _      _   _   _   _  
         / \ / \ / \   / \ / \ / \ / \    / \ / \ / \ / \ 
        ( W | e | b ) ( H | e | l | p )  ( M | e | n | u )
         \_/ \_/ \_/   \_/ \_/ \_/ \_/    \_/ \_/ \_/ \_/    
   """+ m.bcolors.ENDC)

    print(m.bcolors.ERROR + "\t*******************************************************************" + m.bcolors.ENDC)
    print("\t(1)\tEncode and Save To a File")
    print("\t(2)\tEncode and Display")
    print("\t(3)\tDecode String")
    print("\t(99)\tGo back to the main menu")
    print(m.bcolors.BLUE + "\t*******************************************************************" + m.bcolors.ENDC)

    options = input("\nW4@+ R U W@^t1ng Brotein Shake: ")
    if options == "1":
       xss.XSS()
    elif options == "2":
       xxe.XXE()
    elif options == "3":
       ssti.SSTI()
    elif options == "99":
       os.system("clear")
       break
    else:
       input("Hum... are you pr1malbyt3s?...0R...Just Pick something. ")
#! /usr/bin/env python3
import os
import readline
import importlib
from importlib import util
import xml.etree.ElementTree as ET
spec = importlib.util.find_spec('.subserv', package='lib')
m = spec.loader.load_module()
tree = ET.parse('./src/xxeAttacks.xml')
root = tree.getroot()
def ListPayload():
  print("\t**************************************************\n")
  print(m.bcolors.GREEN + m.bcolors.BOLD + m.bcolors.UNDERLINE +"\tHere is the List of possible XXE Payloads\n" + m.bcolors.ENDC)
  for attack in root.findall('attack'):
     name = attack.find('name').text

     print("\tName of XXE Attack: " + m.bcolors.ERROR + m.bcolors.BOLD + name + m.bcolors.ENDC)
#




def complete(text,state):

    xxe = ('XXE_Locator',
        'XXE_Linux_File_Classic_1',
        'XXE_Linux_File_Classic_2',
        'XXE_Linux_File_Classic_3',
        'XXE_Windows_File_Classic',
        'XXE_Linux_Base64_Encoded_Classic',
        'XXE_Windows_Base64_Encoded_Classic',
        'PHP_Wrapper_inside_XXE_1',
        'PHP_Wrapper_inside_XXE_2',
        'XInclude_attack',
        'XXE+SSRF_attack',
        'Error_Based_XXE',
        'Blind_XXE',
        'XXE_OOB_with_DTD_and_PHP_filter',
        'XXE_with_local_DTD',
        'XXE_inside_SVG',
        'XXE_inside_SOAP',
        'XXE_inside_Excel_File'
    )
    options = [i for i in xxe if i.startswith(text)]
    if state < len(options):
        return options[state]
    else:
        return None



def PickPayload():
  readline.parse_and_bind("tab: complete")
  readline.set_completer(complete)
  print("\t**************************************************\n")
  choice = input("\tWhich Payload do you want to use?: ")
  for attack in root.findall('attack'):
     name = attack.find('name').text
     code = attack.find('code').text
     desc = attack.find('desc').text
     if name == choice:
         print("\tName of XXE Attack: " + m.bcolors.ERROR + m.bcolors.BOLD + name + m.bcolors.ENDC)
         print("\n\n\tThe C0de is: " + m.bcolors.ERROR + m.bcolors.BOLD + code + m.bcolors.ENDC)
         print("\n\n\tDescription of attack: " + m.bcolors.ERROR + m.bcolors.BOLD + desc + m.bcolors.ENDC)
         input("Press any key to go back to the menu!")

def XXE():
    os.system("clear")
    while (1):
        print(m.bcolors.BLUE + "\t*******************************************************************" + m.bcolors.ENDC)
        print(m.bcolors.BOLD + m.bcolors.GREEN + """
        *******************************************************************
          _   _   _     _   _   _   _   _   _   _     _   _   _   _  
         / \ / \ / \   / \ / \ / \ / \ / \ / \ / \   / \ / \ / \ / \ 
        ( X | X | E ) ( P | a | y | l | o | a | d ) ( M | e | n | u )
         \_/ \_/ \_/   \_/ \_/ \_/ \_/ \_/ \_/ \_/   \_/ \_/ \_/ \_/                  """ + m.bcolors.ENDC)

        print(
            m.bcolors.ERROR + "\t*******************************************************************" + m.bcolors.ENDC)
        print("\t(1)\tList XXE Payloads")
        print("\t(2)\tPick XXE Payload")
        print("\t(99)\tGo back to the Custom Main Menu")
        print(m.bcolors.BLUE + "\t*******************************************************************" + m.bcolors.ENDC)

        options = input("\nW4@+ Payload R U W@^t1ng Broliath: ")
        if options == "1":
           ListPayload()
        elif options == "2":
           PickPayload()
        elif options == "99":
           os.system("clear")
           break
        else:
           input("GO CHIEFS! Come on pick something... ")


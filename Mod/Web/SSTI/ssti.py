#! /usr/bin/env python3
import os
import readline
import importlib
from importlib import util
import xml.etree.ElementTree as ET
spec = importlib.util.find_spec('.subserv', package='lib')
m = spec.loader.load_module()
tree = ET.parse('./src/sstiAttacks.xml')
root = tree.getroot()


def ListPayload():
  print("\t**************************************************\n")
  print(m.bcolors.GREEN + m.bcolors.BOLD + m.bcolors.UNDERLINE +"\tHere is the List of possible SSTI Payloads\n" + m.bcolors.ENDC)
  for attack in root.findall('attack'):
     name = attack.find('name').text

     print("\tName of SSTI Attack: " + m.bcolors.ERROR + m.bcolors.BOLD + name + m.bcolors.ENDC)



def complete(text,state):

    ssti = (
    'Ruby_Basic_ERB', 'Ruby_Basic_Slim', 'Ruby_Read_Files', 'Ruby_List_Directories', 'Java_Basic_1', 'Java_Basic_2',
    'Java_Basic_getPath', 'Java_Basic_getContent', 'Java_Env_Var', 'Java_passwd_1', 'Java_passwd_2', 'Twig_Basic_1',
    'Twig_Basic_2', 'Twig_File_Read', 'Smarty_Version', 'Smarty_C2', 'Freemarker_Basic_1', 'Freemarker_Basic_2',
    'Freemarker_RCE_1', 'Freemarker_RCE_2', 'Freemarker_RCE_3', 'Pebble_Basic_1','Pebble_Basic_2','Pebble_RCE',
    'JinJa2_Basic_1','JinJa2_Basic_2','JinJa2_File_Read','JinJa2_File_Write','JinJa2_POpen_Reverse_Shell',
    'JinJava_Basic','JinJava_RCE','ASP_.NET_Razor','ASP_.NET_Razor_RCE'
         )
    options = [i for i in ssti if i.startswith(text)]
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
         print("\tName of SSTI Attack: " + m.bcolors.ERROR + m.bcolors.BOLD + name + m.bcolors.ENDC)
         print("\n\n\tThe C0de is: " + m.bcolors.ERROR + m.bcolors.BOLD + code + m.bcolors.ENDC)
         print("\n\n\tDescription of attack: " + m.bcolors.ERROR + m.bcolors.BOLD + desc + m.bcolors.ENDC)
         input("Press any key to go back to the menu!")

def SSTI():
    os.system("clear")
    while (1):
        print(m.bcolors.BLUE + "\t*******************************************************************" + m.bcolors.ENDC)
        print(m.bcolors.BOLD + m.bcolors.GREEN + """
        *******************************************************************
          _   _   _   _     _   _   _   _   _   _   _     _   _   _   _  
         / \ / \ / \ / \   / \ / \ / \ / \ / \ / \ / \   / \ / \ / \ / \ 
        ( S | S | T | I ) ( P | a | y | l | o | a | d ) ( M | e | n | u )
         \_/ \_/ \_/ \_/   \_/ \_/ \_/ \_/ \_/ \_/ \_/   \_/ \_/ \_/ \_/ 
         """ + m.bcolors.ENDC)

        print(
            m.bcolors.ERROR + "\t*******************************************************************" + m.bcolors.ENDC)
        print("\t(1)\tList SSTI Payloads")
        print("\t(2)\tPick SSTI Payload")
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


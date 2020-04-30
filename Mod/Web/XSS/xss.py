#! /usr/bin/env python3
import os
import readline
import importlib
from importlib import util
import xml.etree.ElementTree as ET
spec = importlib.util.find_spec('.subserv', package='lib')
m = spec.loader.load_module()
tree = ET.parse('./src/xssAttacks.xml')
root = tree.getroot()
def ListPayload():
  print("\t**************************************************\n")
  print(m.bcolors.GREEN + m.bcolors.BOLD + m.bcolors.UNDERLINE +"\tHere is the List of possible XSS Payloads\n" + m.bcolors.ENDC)
  for attack in root.findall('attack'):
     name = attack.find('name').text

     print("\tName of XSS Attack: " + m.bcolors.ERROR + m.bcolors.BOLD + name + m.bcolors.ENDC)



def complete(text,state):

    xss = ('XSS_Locator','XSS_Quick_Test','SCRIPT_w/Alert()',
'SCRIPT_w/Source_File','SCRIPT_w/Char_Code','BASE','BGSOUND','BODY_background-image','BODY_ONLOAD','DIV_background-image_1',
'DIV_background-image_2','DIV_expression','FRAME','IFRAME','INPUT_Image','IMG_w/JavaScript_Directive',
'IMG_No_Quotes/Semicolon','IMG_Dynsrc','IMG_Lowsrc','IMG_Embedded_commands_1',
'IMG_Embedded_commands_2','IMG_STYLE_w/expression','List-style-image','IMG_w/VBscript','LAYER','Livescript','US-ASCII_encoding','META',
'META_w/data:URL','META_w/additional_URL_parameter','Mocha','OBJECT','OBJECT_w/Embedded_XSS','Embed_Flash','OBJECT_w/Flash_2',
'STYLE','STYLE_w/Comment','STYLE_w/Anonymous_HTML','STYLE_w/background-image','STYLE_w/background','Stylesheet','Remote_Stylesheet_1',
'Remote_Stylesheet_2','Remote_Stylesheet_3','Remote_Stylesheet_4','TABLE','TD','XML_namespace','XML_data_island_w/CDATA',
'XML_data_island_w/comment','XML(locally-hosted)','XML_HTML+TIME','Commented-out_Block','Cookie_Manipulation','Local_.htc_file',
'Rename_.js_to_.jpg','SSI','PHP','JavaScript_Includes','Character_Encoding_Example','Case_Insensitive','HTML_Entities','Grave_Accents',
'Image_w/CharCode','UTF-8_Unicode_Encoding','Long_UTF-8_Unicode_w/out_Semicolons','DIV_w/Unicode',
'Hex_Encoding_w/out_Semicolons','UTF-7_Encoding','Escaping_JavaScript_escapes','End_title_tag','STYLE_w/broken_up_JavaScript','Embedded_Tab',
'Embedded_Encoded_Tab','Embedded_Newline','Embedded_Carriage_Return','Multiline_w/Carriage_Returns','Null_Chars_1','Null_Chars_2','Spaces/Meta_Chars',
'Non-Alpha/Non-Digit','Non-Alpha/Non-Digit_Part_2','No_Closing_Script_Tag','Protocol_resolution_in_script_tags','Half-Open_HTML/JavaScript','Double_open_angle_brackets',
'Extraneous_Open_Brackets','Malformed_IMG_Tags','No_Quotes/Semicolons','Event_Handlers_List_1','Event_Handlers_List_2','Event_Handlers_List_3',
'Evade_Regex_Filter_1','Evade_Regex_Filter_2','Evade_Regex_Filter_3','Evade_Regex_Filter_4','Evade_Regex_Filter_5','Filter_Evasion_1',
'Filter_Evasion_2','IP_Encoding','URL_Encoding','Dword_Encoding','Hex_Encoding','Octal_Encoding','Mixed_Encoding','Protocol_Resolution_Bypass',
'Firefox_Lookups_1','Firefox_Lookups_2','Firefox_Lookups_3','Removing_Cnames','Extra_dot_for_Absolute_DNS','JavaScript_Link_Location','Content_Replace'
    )

    options = [i for i in xss if i.startswith(text)]
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
         print("\tName of XSS Attack: " + m.bcolors.ERROR + m.bcolors.BOLD + name + m.bcolors.ENDC)
         print("\n\n\tThe C0de is: " + m.bcolors.ERROR + m.bcolors.BOLD + code + m.bcolors.ENDC)
         print("\n\n\tDescription of attack: " + m.bcolors.ERROR + m.bcolors.BOLD + desc + m.bcolors.ENDC)
         input("Press any key to go back to the menu!")

def XSS():
    os.system("clear")
    while (1):
        print(m.bcolors.BLUE + "\t*******************************************************************" + m.bcolors.ENDC)
        print(m.bcolors.BOLD + m.bcolors.GREEN + """
        *******************************************************************
          _   _   _     _   _   _   _   _   _   _     _   _   _   _  
         / \ / \ / \   / \ / \ / \ / \ / \ / \ / \   / \ / \ / \ / \ 
        ( X | S | S ) ( P | a | y | l | o | a | d ) ( M | e | n | u )
         \_/ \_/ \_/   \_/ \_/ \_/ \_/ \_/ \_/ \_/   \_/ \_/ \_/ \_/                  """ + m.bcolors.ENDC)

        print(
            m.bcolors.ERROR + "\t*******************************************************************" + m.bcolors.ENDC)
        print("\t(1)\tList XSS Payloads")
        print("\t(2)\tPick XSS Payload")
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


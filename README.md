# aMALgamous<br />
<p align="center">
  <img width="200" height="230" src="/imgs/aMALgamous.png">
</p>
aMALgamous is a collection of payloads, shells, and malware generation. As well as a collection of tips and tricks that I have collected over the years of penetration testing.

## Updates
**Upgrade** January 4, 2021: Added the first edition of SSSHHH C2. This C2 uses AWS S3 Buckets to pass commands and read results. I have only built payloads in python for now. I am planning to make it multi victim capable, but I am still working on the C2 interface.


**NOTE** November 11, 2020: I just fixed a bug that would break aMALgamous if there was an interface on the system that didn't have an IPv4 address. Please update your repositories. 

*THANKS*  :sunglasses:


![GitHub Logo](/imgs/aMAL.png)

## Install
```
git clone https://github.com/Marantral/aMALgamous.git
cd aMALgamous 
sudo ./setup.sh 

You have to make sure that the dpkg --add-architecture i386 worked and you can install x86 packages
```
## Run/Operate
```
python3 aMALgamous.py
```
#### Main Menu <br />
![Alt MM](/imgs/1.png)

#### Malware Menu <br />
![Alt Mal](/imgs/2.png)

#### Shell Menu <br />
![Alt She](/imgs/3.png)

#### Web Help Menu <br />
![Alt Web](/imgs/4.png)

#### SSSHHH C2 <br />
![Alt Web](/imgs/5.png)


Place the c2 python file on your control system and the payload file on the target. All traffic will be routed through AWS S3.
You will need to have a few items to make this work.
- An AWS account
- An AWS key and secret (Make sure that the permissions on it only allows for modification of the S3 buckets).
All other settings and configurations will be done by aMALgamous. 

NOTE: When done you will need to manually clean your S3 buckets that were created.


**All malware will be placed in aMALgamatiom/current with old malware being placed in an arcive folder.** <br />

#### Index
The output is numbered based on function.
- 000-009 --> 32bit basic meterpreter payloads 
- 010-019 --> 64bit basic meterpreter payloads 
- 020-029 --> 64bit basic Shell payloads 
- 030-099 --> Saved for future development 
- 100-199 --> Python payloads 
- 200-299 --> MAC payloads 
- 300-319 --> ICMP and DNS payloads 
- 320-329 --> Regsrv32 32bit meterpreter payloads 
- 330-339 --> Regsrv32 64bit meterpreter payloads 
- 340-349 --> Regsrv32 32bit shell payloads 
- 350-359 --> Regsrv32 64bit shell payloads 
- 370-399 --> Saved for future development 
- 400-409 --> InstallUtil payloads
- 410-419 --> MSBuild payloads 
- 420-429 --> PresentationHost payloads
- 430-439 --> RegAsm payloads 
- 440-449 --> RegSvcs payloads 
- 450-900 --> Saved for futre development

- Custom Malware Creation Help 

#### Shell Payloads
- BASH Reverse Shell --------- (Linux|Unix|Mac)
- PERL Reverse Shell --------- (Linux|Unix|Mac)
- PERL Reverse Shell --------- (Windows)
- PowerShell Reverse Shell --- (Windows)
- Python Reverse Shell ------- (Linx|Unix|Mac)
- Python Reverse Shell ------- (Windows)
- PHP Reverse Shell ---------- (Linux|Unix|Mac)
- Ruby Reverse Shell --------- (Linux|Unix|Mac)
- Ruby Reverse Shell --------- (Windows)
- Golang Reverse Shell ------- (Linux|Unix)
- Awk Reverse Shell ---------- (Linux|Unix)
- Java Reverse Shell --------- (Linux|Unix)
- Java Reverse Shell --------- (Windows)
- OpenSSL Shell -------------- (Linux|Unix|Mac)
- NetCat MAC Shell ------------(Mac) 

#### Web Payload Help
- XSS Payloads -----(Cross Site Scripting)
- XXE Payloads ------(XML External Entity)
- SSTI Payloads------(Server Side Template injection)


***********Functions to Add************ 
1. Add automatic Web and SMB Shares on attack box
2. Add Encoding section..
3. Expand Malware examples
4. Add more web application functionality 
5. Add Domain helps
6. Add priv esc helps 

Thanks to all of the TidePod :+1:



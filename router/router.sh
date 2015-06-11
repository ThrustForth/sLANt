#!/bin/bash
set -x
# Copyright C 2012 Michael Clancy

# Router Assessment Tool
current_menu=""                                        # Interface to Scan With NMap
if [ -e /tmp/menu/targets ] ; then
   model="$(cat /tmp/menu/targets | grep "$gateway " | awk '{ print $6 }' | sed 's/[)(]//g')"                                           # Router Model
else
   netdiscover
fi

exploit_list="$(ls /root/Desktop/current/attack/router/exploits | grep $model)"
brute_hydra="$(ls /root/Desktop/current/attack/router/brute/hydra | grep $model)"
brute_imacros="$(ls /root/Desktop/current/attack/router/brute/imacros | grep $model)"

function display() { #display type message
      output=""
      if [ "$1" == "action" ]; then output="\e[01;32m[>]\e[00m"
      elif [ "$1" == "info" ]; then output="\e[01;33m[i]\e[00m"
      elif [ "$1" == "diag" ]; then output="\e[01;34m[+]\e[00m"
      elif [ "$1" == "error" ]; then output="\e[01;31m[!]\e[00m"; fi
      output="$output $2"
      echo -e "$output"

      if [ "$diagnostics" == "true" ]; then
         if [ "$1" == "action" ]; then output="[>]"
         elif [ "$1" == "info" ]; then output="[i]"
         elif [ "$1" == "diag" ]; then output="[+]"
         elif [ "$1" == "error" ]; then output="[!]"
         fi
      fi
}


if [ "$model" == "$exploit_list" ] ; then display info "Found Exploit Method For $model" ; fi
if [ "$model" == "$brute_hydra" ] ; then display info "Found Hydra Brute Method For $model" ; fi
if [ "$model" == "$brute_imacros" ] ; then display info "Found IMacros Brute Method For $model" && /root/Desktop/current/attack/router/brute/imacros/$model $gateway ; fi
                                                                 # Router Attack Menu
current_menu="router"
info
echo
echo -e "\e[01;36m<<Router Menu>>\e[00m"
echo -e "\e[01;36m1)\e[00m Try Exploit"
echo -e "\e[01;36m2)\e[00m Hydra - Brute Force"
echo -e "\e[01;36m3)\e[00m IMacros - Brute Force"
echo -e "\e[01;36mQ)\e[00m Return to the Network Menu"
echo
command="$(display action)"
read -p "$command Choose Option >>> " Menuchoice

case $Menuchoice in
1 ) router_scan ;;
2 ) router_brute ;;
3 ) router_exploit ;;
q ) network ;;
e ) external_ip ;;
s ) netdiscover ;;
c ) clear_targets ;;
v ) nmap_util view ;;
* ) network ;;
esac
$current_menu
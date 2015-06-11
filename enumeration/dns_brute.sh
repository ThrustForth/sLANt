#!/bin/bash

domain=$1

y=1
x="$(wc /root/Desktop/tools/enumeration/dns_prefix | awk '{ print $1}')"
   item="$(cat /root/Desktop/tools/enumeration/dns_prefix)"
   for m in ${item[@]} ; do
   y=$(($y+1))
      ping -w 2 -c 1 $m.$domain > /dev/null
      a="$(echo $?)"
#      alive="$(echo $?)"
#      if [ "$(ping -w 4 -q -c1 $m.$domain 2>/dev/null)" ] ; then
         if [ $a == "0" ] ; then
            printf "$m.$domain\n" >> /tmp/menu/dns_$domain
         fi
         #clear
#      fi
      clear
      printf "$y of $x - Complete"
   done
clear
cat /tmp/menu/dns_$domain
#rm /tmp/menu/found_$domain

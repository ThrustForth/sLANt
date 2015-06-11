#!/bin/bash
# set -x
ourIP="$1"
networkmask="$2"
interface="$3"
broadcast="$4"

#----------------------------------------------------------------------------------------------#
   while [ "$loopMain" != "true" ]; do
      ip4="${ourIP##*.}"; x="${ourIP%.*}"
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
            255) let nbits+=8;;
            254) let nbits+=7;;
            252) let nbits+=6;;
            248) let nbits+=5;;
            240) let nbits+=4;;
            224) let nbits+=3;;
            192) let nbits+=2;;
            128) let nbits+=1;;
            0);;
            *) display error "Bad input: dec ($dec)" 1>&2; cleanUp
          esac
      done
      IFS=$oldIFS
      echo "Scanning Targets"
      nmap $subnet/$nbits -e $interface -n -sP -sn | tee /tmp/sitm.tmp #-O -oX sitm.nmap.xml
      echo -e " Num |        IP       |       MAC       |     Hostname    |   Hardware  \n-----|-----------------|-----------------|-----------------|--------"
      arrayTarget=( $(cat "/tmp/sitm.tmp" | grep "Nmap scan report for" | grep -v "host down" |  sed 's/Nmap scan report for //') )
      i="0"
      for targets in "${arrayTarget[@]}"; do
         macaddress=$(cat "/tmp/sitm.tmp" | grep $targets -A 3 | grep "MAC Address: " | head -1 | awk '{ print $3 }' )
         hardware=$(cat "/tmp/sitm.tmp" | grep $targets -A 3 | grep "MAC Address: " | head -1 | awk '{ print $4$5$6 }' )
         printf "  %-2s | %-15s |$macaddress| %-15s | $hardware \n" "$(($i+1))" "${arrayTarget[${i}]}"
         i=$(($i+1))
      done
      echo "  $(($i+1))  | $broadcast   | *Everyone*"
      loopSub="false"
      while [ "$loopSub" != "true" ]; do
         if [ "$5" == "aggressive" ] ; then
            read -p "[~] re[s]can, [m]anual, e[x]it or select num: "
            if [ "$REPLY" == "x" ]; then cleanUp clean
            elif [ "$REPLY" == "m" ]; then read -p "[~] IP address: "; target="$REPLY" loopSub="true"; loopMain="true"
            elif [ "$REPLY" == "s" ]; then loopSub="true"
            elif [ -z $(echo "$REPLY" | tr -dc '[:digit:]'l) ]; then display error "Bad input" 1>&2
            elif [ "$REPLY" -lt "1" ] || [ "$REPLY" -gt "$i" ]; then display error "Incorrect number" 1>&2
            else target=${arrayTarget[$(($REPLY-1))]}; loopSub="true"; loopMain="true"
            fi
         else
            exit 0
         fi
      done
   done
echo $target

if [ "$5" == "aggressive" ] ; then
   nmap -A $target -oN /tmp/aggressive_scan
fi
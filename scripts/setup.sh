#!/bin/bash

# exit var
int_found=0

# config var
NAME="mon0"
CH="1"
BAND="HT40+"
BITR="mcs-5 4"

# Is there any wireless interface
for WINT in $(iwconfig 2> /dev/null | grep "IEEE 802.11bgn" | cut -d" " -f1)
do
	is_Monitor=$(iwconfig $WINT 2>/dev/null | grep "IEEE 802.11bgn  Mode" | cut -d":" -f2 | cut -d" " -f1)
	if [ "$WINT" == "$NAME" ] && [ "$is_Monitor" == "Monitor" ]
	then
		echo "Interface $NAME is created already as $is_Monitor ..."
		int_found=1
	else
		echo "Found $WINT as $is_Monitor and removing it ..."
		iw dev $WINT del
	fi
done	

# Lets find phy interface
WPHY=$(iw list 2> /dev/null | grep "Wiphy" | cut -d" " -f2)
echo "Phy : $WPHY"

# Lets find interface number
WNUM=$(rfkill list 2> /dev/null | grep "$WPHY" | cut -d":" -f1)
echo "Phy num : $WNUM"

# Lets unblock it
rfkill unblock $WNUM

if [ $int_found -ne 1 ]
then
	# Lets crate intefcae
	iw phy $WPHY interface add $NAME type monitor flags active
else
	# Lets set the flag
	iw dev $NAME set monitor active
fi

# Bring it up
ip link set dev $NAME up

# Set channel
iw dev $NAME set channel $CH

# Set channel with band
#iw dev $NAME set channel $CH $BAND

# Set bitrate
#iw dev $NAME set bitrates $BITR

# Check is it all ok
WINT=$(iwconfig 2> /dev/null | grep "IEEE 802.11bgn" | cut -d" " -f1)
is_Monitor=$(iwconfig $NAME 2>/dev/null | grep "IEEE 802.11bgn  Mode" | cut -d":" -f2 | cut -d" " -f1)

if [ "$WINT" == "$NAME" ] && [ "$is_Monitor" == "Monitor" ]
then
	echo "Interface $NAME created ..."
else
	echo "Somthing wrong ..."
	exit 1
fi

exit 0

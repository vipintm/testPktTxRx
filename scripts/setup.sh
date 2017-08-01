#!/bin/bash

NAME="mon0"
CH="1"
BAND="HT40+"
BITR="mcs-5 4"

# Is there any wireless interface
WINT=$(iwconfig 2> /dev/null | grep "IEEE 802.11bgn" | cut -d" " -f1)

# Remove if found
# Normal case, at boot only 1 interface is created
if [ -z $WINT ]
then
	echo "Found $WINT, and removing it ..."
	iw dev $WINT del
fi

# Lets find phy interface
WPHY=$(iw list 2> /dev/null | grep "Wiphy" | cut -d" " -f2)
echo "Phy : $WPHY"

# Lets find interface number
WNUM=$(rfkill list 2> /dev/null | grep "$WPHY" | cut -d":" -f1)
echo "Phy num : $WNUM"

# Lets unblock it
rfkill unblock $WNUM

# Lets crate intefcae
iw phy $WPHY interface add $NAME type monitor flags active

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

if [ "$WINT" == "$NAME" ]
then
	echo "Interface $NAME created ..."
else
	echo "Somthing wrong ..."
	exit 1
fi
exit 0

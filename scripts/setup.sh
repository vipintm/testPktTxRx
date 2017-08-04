#!/bin/bash

# exit var
int_found=0

# Is there any wireless interface
function check_interface()
{
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
}

# Lets find phy interface
function find_phy()
{
	WPHY=$(iw list 2> /dev/null | grep "Wiphy" | cut -d" " -f2)
	echo "Phy : $WPHY"
}

# Lets find interface number
function find_phy_no()
{
	WNUM=$(rfkill list 2> /dev/null | grep "$WPHY" | cut -d":" -f1)
	echo "Phy num : $WNUM"
}

# Lets unblock it
function unblock_phy()
{
	rfkill unblock $WNUM
}

function create_int()
{
	if [ $int_found -ne 1 ]
	then
		# Lets crate intefcae
		iw phy $WPHY interface add $NAME type monitor flags active
	else
		# Lets set the flag
		iw dev $NAME set monitor active
	fi
}

# Bring it up
function up_int()
{
	ip link set dev $NAME up
}

# Set channel
function set_channel()
{
	iw dev $NAME set channel $CH

	# Set channel with band
	if [ ! -z $BAND ]
	then
		iw dev $NAME set channel $CH $BAND
	fi
}

# Set bitrate
function set_bitrate()
{
	if [ ! -z $BITR ]
	then
		iw dev $NAME set bitrates $BITR
	fi
}

# Set power
function set_power()
{
	if [ "$POWER" == "max" ]
	then
		iw dev $NAME set txpower fixed 20mBm
	else
		iw dev $NAME set txpower fixed $POWER
	fi
} 

# Check is it all ok
function is_inter_ok()
{
	WINT=$(iwconfig 2> /dev/null | grep "IEEE 802.11bgn" | cut -d" " -f1)
	is_Monitor=$(iwconfig $NAME 2>/dev/null | grep "IEEE 802.11bgn  Mode" | cut -d":" -f2 | cut -d" " -f1)

	if [ "$WINT" == "$NAME" ] && [ "$is_Monitor" == "Monitor" ]
	then
		echo "Interface $NAME created ..."
	else
		echo "Somthing wrong ..."
		exit 1
	fi
}

function setup_int()
{
	check_interface
	find_phy
	find_phy_no
	unblock_phy
	create_int
	up_int
	set_channel
	set_bitrate
	set_power
	# at last
	is_inter_ok
}

if [ -z "$1" ]
then
        echo "init setup ..."
elif [ "${0##*/}" == "setup.sh" ]
then
	echo "Run setup ..."
	setup_int	
else
        echo "Somthing gone wrong ..."
fi


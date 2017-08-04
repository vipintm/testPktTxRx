#!/bin/bash

# config var
NAME="mon0"
CH="1"
# BAND="HT40+"
# BITR="mcs-5 4"
POWER="max"
SPATH="/media/realroot"

echo "Lets run setup ..."
if [ -f $SPATH/setup.sh ]
then
	. $SPATH/setup.sh
	setup_int
elif [ -f script/setup.sh ]
then
	. script/setup.sh
else
	echo "Unable to find setup script, exit ..."
	exit 1
fi

echo "Let start test ..."
if [ -f $SPATH/$1 ]
then
	chmod 755 $SPATH/$1
	./$SPATH/$1
elif [ -f build/$1 ]
then
	chmod 755 build/$1
	./build/$1
else
	echo "Unable to find $1, exit ..."
	exit 1
fi

exit $?

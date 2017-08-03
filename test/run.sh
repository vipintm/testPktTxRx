#!/bin/bash

# config var
NAME="mon0"
CH="1"
# BAND="HT40+"
# BITR="mcs-5 4"

echo "Lets run setup ..."
if [ -f setup.sh ]
then
	. setup.sh
	setup_int
else
	echo "Unable to find setup script, exit ..."
	exit 1
fi

echo "Let start test ..."
if [ -f $1 ]
then
	chmod 755 $1
	./$1
else
	echo "Unable to find $1, exit ..."
	exit 1
fi

exit $?

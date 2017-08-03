#!/bin/bash
echo $PWD
echo "Lets run setup ..."
if [ -f setup.sh ]
then
	./setup.sh
else
	echo "Unable to find setup scipt, exit ..."
	exit 1
fi

echo "Let start test ..."
if [ -f $1 ]
then
	./$1
else
	echo "Unable to find $1, exit ..."
	exit 1
fi

exit $?

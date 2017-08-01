#!/bin/bash

echo "Lets run setup ..."
./setup.sh
echo "Let start test ..."
$1

exit $?

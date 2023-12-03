#!/bin/bash

# Check if the file name is given as an argument
if [ $# -ne 1 ]; then
    echo "Usage: $0 <filename>"
    exit 1
fi

# Check if the file exists
if [ ! -f "$1" ]; then
    echo "File not found: $1"
    exit 1
fi
# Change the owner of the file to root
chown root "$1"
# Set the SUID bit for the file
chmod u+s "$1"

echo "File $1 is now set to SUID of root"
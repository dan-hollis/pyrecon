#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "Run as root." 
   exit 1
fi

go version &>is.go.installed.tmp
if [[ $(cat is.go.installed.tmp) = *"command not found"* ]]; then
	echo "Go install not found. Check README for info on setting up a Go environment."
	rm is.go.installed.tmp
	exit 1
fi
rm is.go.installed.tmp

# System update and installs
apt-get update && apt-get -y dist-upgrade && apt -y autoremove && apt-get clean
apt-get install -y git firefox-esr xsltproc nmap masscan dnsrecon python python-pip python3 python3-pip

# Pip installs
wget -nc -P /opt/ https://bootstrap.pypa.io/get-pip.py
python /opt/get-pip.py --prefix=/usr/local/
python3 -m pip install --upgrade pip setuptools wheel requests beautifultable python_whois pyfiglet ipwhois beautifulsoup4 termcolor whois

git clone https://github.com/maaaaz/nmaptocsv /opt/nmaptocsv
chmod +x /opt/nmaptocsv/nmaptocsv.py
ln -sf /opt/nmaptocsv/nmaptocsv.py /usr/local/bin/nmaptocsv

git clone https://github.com/FortyNorthSecurity/EyeWitness /opt/eyewitness
chmod +x /opt/eyewitness/EyeWitness.py
ln -sf /opt/eyewitness/EyeWitness.py /usr/local/bin/eyewitness

# go tool installs
go get -u github.com/OWASP/Amass/...
go get -u github.com/subfinder/subfinder

# Get the full path of the current directory (pyrecon/setup)
# Remove /setup from the path to get the full path of the main pyrecon directory
#PYRECON_DIRECTORY=$(dir=$(pwd); echo ${dir%*/setup})
#cd $PYRECON_DIRECTORY/setup

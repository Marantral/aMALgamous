#!/bin/bash
dpkg --add-architecture i386
apt-get  update -y
apt-get -y  install mono-complete mono-mcs python3-pip
pip3 install netifaces boto3

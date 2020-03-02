#!/bin/bash
dpkg --add-architecture i386
apt-get  update -y
apt-get -y  install mono-complete mono-mcs unzip wget git ruby p7zip wine wine32 wine64 winbind


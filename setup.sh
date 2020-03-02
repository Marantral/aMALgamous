#!/bin/bash
dpkg --add-architecture i386
apt-get  update -y
apt-get -y  install mono-complete mono-mcs wine wine32 wine64 winbind


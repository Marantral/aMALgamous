#!/bin/bash

#ignoring echo replys. Without this icmpsh will not work
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#Running the icmpsh listener 
perl /opt/icmpsh/icmpsh-m.pl



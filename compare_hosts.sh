#!/bin/bash
debug=0
while getopts "d" opt; do
	case "%opt" in
	d) debug=1;;
	esac
done
make
echo IP addresses: > resolved_ips.txt
while read line
do	
	echo Resolving $line
	echo hw3 resolver: >> resolved_ips.txt
	if (( $debug == 1 )); then
		./hw3 -d -i $line >> resolved_ips.txt
	else
		./hw3 -i $line >> resolved_ips.txt
	fi
	echo host resolver: >> resolved_ips.txt
	host $line >> resolved_ips.txt
	echo >> resolved_ips.txt
done < hostnames.txt
cat resolved_ips.txt

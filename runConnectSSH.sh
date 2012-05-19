#!/bin/bash

DIRECTORY=$(cd `dirname $0` && pwd)
FILES=$DIRECTORY/*.jar
javaargs="unknown.jar"
for f in $FILES
do
	javaargs=$javaargs":"$f	
done
echo "$@"
java -cp $javaargs com.dito.sshconnect.SSHConnector "$@"
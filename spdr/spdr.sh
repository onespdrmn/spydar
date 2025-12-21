#!/bin/bash

ps uax|grep python3|grep -v grep |grep http.server|awk {'print $2'} |xargs kill -9

cd inputs
python3 -m http.server  &
sleep 1

cd ..
./spdr.linux


# ScapyGELFtoGraylog2
sniff some 802.11 packages and send the date en MAC with GELF UDP to Graylog2

This Python script [1] will sniff three management frame subtypes in 802.11: 0, 2 and 4 and will send it to Graylog2. Make sure you first set the interface you want to use in monitoring mode, before starting this script: airmon-ng start wlan0. Also, make sure you have a GELF UDP listener ready on SentToHost:SentToPort. Start it with something like `/home/pi/sniff.py` and see it eeting your RAM ;). This script works with Python 2.7.9 on a Raspberry Pi with Domoticz [3] installed on it. This is version ALPHA 0.0002 of the script. Use at your own risk.

[1] Most of the code comes from: https://pen-testing.sans.org/blog/2011/10/13/special-request-wireless-client-sniffing-with-scapy
[3] For home automation, please see http://domoticz.com/

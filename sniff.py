#!/usr/bin/env python
# The previous line ensures that this script is run under the context
# of the Python interpreter. Next, import the Scapy functions:
from scapy.all import *
from subprocess import call
import time
#IP and hostname where to send the GELF UDP packages to
SentToHost = "192.0.2.1"
SentToPort = "12201"
#enter the location that you are running this sniffer from; like home, or Garlicstreet 3 or whatever
location = "home"


print "---- INSTRUCTIONS ----"
print " "
print "This Python script will sniff three management frame subtypes in 802.11: 0, 2 and 4 and will send it to Graylog2. Make sure you first set the interface you want to use in monitoring mode, before starting this script: airmon-ng start wlan0. Also, make sure you have a GELF UDP listener ready on " + SentToHost + ":" + SentToPort + ". In the same directory as this script, store the file you get from https://gist.github.com/derlinkshaender/5995776 and name it graylogger.py."
print " "
print "---- THIS PROGRAM IS \"AS IS\" WITHOUT WARRANTY OF ANY KIND ----"
    
# Define the interface name that we will be sniffing from, you can
# change this if needed.
interface = "mon0"

# Next, declare a Python list to keep track of client MAC addresses
# that we have already seen so we only print the address once per client.
observedclients = []

# The sniffmgmt() function is called each time Scapy receives a packet
# (we'll tell Scapy to use this function below with the sniff() function).
# The packet that was sniffed is passed as the function argument, "p".
def sniffmgmt(p):

    # Define our tuple (an immutable list) of the 3 management frame
    # subtypes sent exclusively by clients. I got this list from Wireshark.
    stamgmtstypes = (0, 2, 4)
    
    
    # Make sure the packet has the Scapy Dot11 layer present
    if p.haslayer(Dot11):

        # Check to make sure this is a management frame (type=0) and that
        # the subtype is one of our management frame subtypes indicating a
        # a wireless client
        if p.type == 0 and p.subtype in stamgmtstypes:

            # We only want to print the MAC address of the client if it
            # hasn't already been observed. Check our list and if the
            # client address isn't present, print the address and then add
            # it to our list.
            if p.addr2 not in observedclients:
                localtime = time.asctime( time.localtime(time.time()) )
                print localtime + " " + p.addr2
                subprocess.call("./graylogger.py -l INFO -f \"SNIFFER\" -p " + SentToPort + " " + SentToHost + " " + p.addr2 + " -d \"epoch:`date +%s`\" -d \"client_mac:true\" -d location:" + location, shell=True)
                observedclients.append(p.addr2)

# With the sniffmgmt() function complete, we can invoke the Scapy sniff()
# function, pointing to the monitor mode interface, and telling Scapy to call
sniff(iface=interface, prn=sniffmgmt)

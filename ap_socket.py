#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# +++++++++++++++++++++++++++++++++++++++++
#
#	WLAN BEACON FRAME EXTRACTOR	
# +++++++++++++++++++++++++++++++++++++++++
#
#
# Author :	SSB
#		surajsinghbisht054@gmail.com
#		http://bitforestinfo.blogspot.com
#		github.com/surajsinghbisht054
#
#
# This Script Is Created For Educational And Practise Purpose Only
#
#
# import module
import socket
import struct

# create Socket
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

# bind with monitor mode interface
s.bind(('mon0',0x0003))


# function for formating mac addresses
def addr(s):
	return "{}{}:{}{}:{}{}:{}{}:{}{}:{}{}".format(*s.upper())

# Founded Access Point List
ap_list = []


# loop
while True:
	# Sniff Packet and get packet from list
	pkt = s.recvfrom(2048)[0]

	# Check RadioTap Header Frame In Packet
	if pkt[2:4]=='$\x00':

		# Get Total Length Of RadioTap Header Packet Bytes
		len_of_header = struct.unpack('h', pkt[2:4])[0]

		# Extract RadioTap Header
		radio_tap_header_frame = pkt[:len_of_header].encode('hex')

		# Now, assume that next frame from radiotap is Beacon Frame
		beacon_frame = pkt[len_of_header:len_of_header+24].encode('hex')

		# Frame Type
		f_type = beacon_frame[:2]

		# Extract Addr1
		addr1  = beacon_frame[8:20]

		# Extract Addr2
		addr2  = beacon_frame[20:32]

		# Extract Addr3
		addr3  = beacon_frame[32:44]

		# Try To Extract SSID if present
		try:
			len_of_ssid = ord(pkt[73])
			ssid   = pkt[74:74+len_of_ssid]
		except:
			ssid = "Unknown"

		# Verify that extract frame is a beacon frame and not printed yet
		if addr2 not in ap_list and f_type=='80':

			# append addr2 in ap_list 
			ap_list.append(addr2)

			# Print Info
			print """
++++++++++ [ Beacon Frame ] ++++++++++++++++++++

Frame Type	:	{}
SSID		:	{}
Receiver	:	{}
Transmitter	:	{}
Source		:	{}


			""".format(f_type,	# Frame Type
				ssid ,		# SSID
				addr(addr1), 	# Addr1
				addr(addr2), 	# Addr2
				addr(addr3)	# Addr3
				)


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
# import scapy module
import scapy.all as scapy


# Extracted Packet Format 
Pkt_Info = """
---------------[ Packet Captured ]-----------------------
 Subtype 	: {}
 Address 1 	: {}
 Address 2	: {} [BSSID]
 Address 3 	: {}
 Address 4	: {}
 AP		: {} [SSID]

"""

# Founded Access Point List
ap_list = []

# For Extracting Available Access Points
def PacketHandler(pkt) :
	#
	# pkt.haslayer(scapy.Dot11Elt)
	#
	# 	This Situation Help Us To Filter Dot11Elt Traffic From
	# 	Various Types Of Packets
	#
	# pkt.type == 0 
	#
	#	This Filter Help Us To Filter Management Frame From Packet
	#
	# pkt.subtype == 8 
	#
	#	This Filter Help Us To Filter Becon From From Captured Packets
	#
	# p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp)
	if pkt.haslayer(scapy.Dot11Beacon) or pkt.haslayer(scapy.Dot11ProbeResp):
		# 
		# This Function Will Verify Not To Print Same Access Point Again And Again
		#
		if pkt.addr2 not in ap_list:
			#
			# Append Access Point
			#
			ap_list.append(pkt.addr2)
			#
			# Print Packet Informations
			#
 			print Pkt_Info.format(pkt.subtype,pkt.addr1, pkt.addr2, pkt.addr3, pkt.addr4, pkt.info)
	
# Main Trigger
if __name__=="__main__":

	# Previous Function Trigger
	#
	# here, iface="mon0" for Interface with monitor mode enable
	# 
	scapy.sniff(iface="mon0", prn = PacketHandler, timeout=60)


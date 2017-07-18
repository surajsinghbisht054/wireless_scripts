#!/usr/bin/python

"""
===============================================================
++++++++++++++++++++++++ READ ME ++++++++++++++++++++++++++++++
===============================================================

This Script Is Part Of 

		+++++++++++++++++++++++++++++++++++++
			Simple Wireless Framework
		+++++++++++++++++++++++++++++++++++++



Author :

    	Suraj Singh
    	Admin
    	S.S.B Group
    	surajsinghbisht054@gmail.com
    	www.bitforestinfo.com


    	Note: We Feel Proud To Be Indian


This Script Created Only For Practise And Educational Purpose Only
The Author Will Not Take Any Responsibility Of Any illegal Activity.

"""
# 
# Live Beacon Packets Analyser
# 
# This Script is Based On Pyshark
#
#
#

# import module
import pyshark
import sys

# Required Data Feild
Feild = {
	# Key      Value  Required
	'interface'  : (None, True),
	}


# Format For Printing Beacon Data
BEACON_FORMAT = '\t {bssid} {type}     {subtype}        {data_rate}     {frequency}           {channel}         {signal}   {addr}    {ssid} {num}'

# Label
print '\t BSSID             #Type #Subtype #Rate #Frequency  #Channel  #Signal  #ADDR               #ESSID		#Beacon'



def display_info(data):
	line = 0
	for a,b in data.iteritems():
		print BEACON_FORMAT.format(**b)
		line+=1

	# Backspace Trick
	sys.stdout.write("\033[{}A".format(line))
	return



# Function For Extracting From pyshark Packets
def ap_info_extractor(pkt):
	'''
	Extracting Various Values.

	Labels :
		bssid
		type
		subtype
		addr
		channel
		frequency
		signal
		data_rate
		phy
		ssid


	'''
	ref = {} 
	ref['bssid'] 	= pkt.wlan.bssid
	ref['type'] 	= pkt.wlan.fc_type
	ref['subtype'] 	= pkt.wlan.fc_type_subtype
	ref['addr'] 	= pkt.wlan.addr
	ref['channel'] 	= pkt.wlan_radio.channel
	ref['frequency']= pkt.wlan_radio.frequency
	ref['signal']	= pkt.wlan_radio.signal_dbm
	ref['data_rate']= pkt.wlan_radio.data_rate
	ref['phy'] 		= pkt.wlan_radio.phy
	ref['ssid'] 	= pkt.wlan_mgt.ssid
	#ref['psk'] 		= pkt.wlan_mgt.rsn_akms_list

	return ref


# Live Sniffing Function
def wlan_sniffer(cap):
	"""
	Function For Sniffing Live Beacon Packets From Interface
	Based On Pyshark LiveCapture.

	"""
	
	# Captured Bssid List
	bssid_list = {}

	# Get Packets
	for num, packets in enumerate(cap):
		
		# Extract Information From Packet
		data = ap_info_extractor(packets)

		# Packet Num
		data['num'] = num

		# Append Data In Captured Bssid List
		bssid_list[data['bssid']]=data

		# Display Captured Packets Information
		display_info(bssid_list)
	return

# Main Function 
def main(**kwargs):
	"""
	creating pyshark.LiveCapture Object With Beacon Filter Engaged.
	"""
	cap = pyshark.LiveCapture(display_filter="wlan.fc.type_subtype == 0x0008",**kwargs)
	
	# Live Sniffing Function
	wlan_sniffer(cap)

	return


if __name__=='__main__':

	# Get Arguments
	args = sys.argv
	
	if len(args)!=2:
		# Check Interface Name Condition
	
		print "[*] Please Provide Interface Name :\n :~# python {} [Interface_name]".format(args[0])
		sys.exit(0)
	
	# Interface Name
	interface = args[1]
	
	# Trigger Main
	main(interface=interface)

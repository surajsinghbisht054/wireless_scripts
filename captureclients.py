#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# +++++++++++++++++++++++++++++++++++++++++
#
#	WLAN Capture Client Script	
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
import scapy.all as scapy
import sys


#
# Class For Storing/Handling Client And Station Informations
# 


class HandleClients:
	'''
	This Class Provides Simple But Effective Way To Store
	Client And Station MAC Address.

	'''

	def __init__(self):
		self.records = [None,]
		self.lastpacket = None

	def save(self, data):
	'''
	Save Data In Records If its Not Already Exist.
	'''

		if data not in self.records:
			self.records.append(data)
			self.lastpacket = data
			return self.lastpackets()
	def getall(self):
	'''
	Return All Saved Records
	'''

		self.records.remove(None)
		return self.records

	def lastpackets(self):
		if not self.lastpacket:
			return

		f1 = self.lastpacket[3]
		f = self.lastpacket
		if f1=='association_request':
			form = '< Station : {} | Client : {} | StationInfo : {} | Layer : {} >'.format(f[0], f[1], f[2], f[3])

		elif f1=='association_response':
			form = '< Station : {} | Client : {} | ClientInfo : {} | Layer : {} >'.format(f[1], f[0], f[2], f[3])

		elif f1=='authentication':
			form = '< DeviceOne : {} | DeviceTwo : {} | DeviceInfo : {} | Layer : {} >'.format(f[0], f[1], f[2], f[3])

		elif f1=='probe_request':
			form = '< Station : {} | Client : {} | ClientInfo : {} | Layer : {} >'.format(f[0], f[1], f[2], f[3])

		elif f1=='probe_answer':
			form = '< Station : {} | Client : {} | StationInfo : {} | Layer : {} >'.format(f[1], f[0], f[2], f[3])

		else:
			form = str(f)
		self.lastpacket = None
		return form

#
# Main Class For Sniffing And Packets Extracting
#
class GetClients:
	def __init__(self, **kwargs):
		'''
		Function For Automatic Packet Sniffing And Handling.
		'''
		self.kwargs = kwargs
		self.handler = HandleClients()
		self.CapturePackets()
		self.showresults()


	def showresults(self):
		'''
		Show All Captured Packets With MAC Address Details.
		'''
		print "\n\t\tFinal Result"
		print " ==> [{}] | [{}] | [{}] | [{}] <==".format("   Station       ","        Client   ", "        Info      ", "     Layer        ")
		for a,b,c,d in self.handler.getall():
			print " ==> [{}] | [{}] | [{}] | [{}] <==".format(a,b,c.ljust(18),d.ljust(18))
		return


	def CapturePackets(self):
		'''
		Scapy Sniff Function
		'''
		scapy.sniff(prn = self.GetAcessClient, **self.kwargs)
		return


	def GetAcessClient(self, pkt):
		'''
		Function For Extracting Various Layers From Captured Packet.
		
		    Supported Layers For Extracting Client And Station MAC Address

			scapy.Dot11AssoReq	=	 Association Request
			scapy.Dot11AssoResp	=	 Association Response
			scapy.Dot11Auth		=	 Authentication
			scapy.Dot11ProbeReq	=	 Probe Request
			scapy.Dot11ProbeResp	=	 Probe Answer
			

		'''
		if pkt.haslayer(scapy.Dot11AssoReq):
			# Association Request
			# print " [*] Association Request."
			data = (station, client, stationinfo, packet) = (pkt.addr1, pkt.addr2, pkt.info, 'association_request')
			get = self.handler.save(data)
			if get:
				print get 
	
	
		if pkt.haslayer(scapy.Dot11AssoResp):
			# Association Response
			# print " [*] Association Response."
			data = (client, station, clientinfo, packet) = (pkt.addr1, pkt.addr2, pkt.info, 'association_response')
			get = self.handler.save(data)
			if get:
				print get
		
		if pkt.haslayer(scapy.Dot11Auth):
			# Authentication
			# print " [*] Authentication. "
			data = (device1, device2, info, packet)=(pkt.addr1, pkt.addr2, pkt.info, 'authentication')
			get = self.handler.save(data)
			if get:
				print get
		if pkt.haslayer(scapy.Dot11ProbeReq):
			# Probe Request
			# print " [*] Probe Request."
			data = (station, client, clientinfo, packet)=(pkt.addr1, pkt.addr2, pkt.info, 'probe_request')		
			get = self.handler.save(data)
			if get:
				print get	
		if pkt.haslayer(scapy.Dot11ProbeResp):
			# Probe Answer
			# print " [*] Probe Answer."
			data = (client, station, stationinfo, packet)=(pkt.addr1, pkt.addr2, pkt.info, 'probe_answer')
			get = self.handler.save(data)
			if get:
				print get	
		return


# Main Trigger 
if __name__=="__main__":
	if sys.argv:
		acp=sys.argv[1]
		GetClients(iface="mon0",timeout=60)
			

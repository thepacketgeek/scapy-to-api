from scapy.all import *
import requests
import json
from datetime import datetime

def cleanPayload(p):
	p = str(p)
	# Clean up packet payload from scapy output
	return p.split('Raw')[0].split("Padding")[0].replace('|','\n').strip('<')\
		.strip('bound method Ether.show of ').replace('>','').replace('[<','[')\
		.replace('\n<','<').replace('<','\n')

def uploadPacket(url, token):

	def parseAndPost(rawPacket):
		# If we can't parse the packet, we don't want to end the sniffing.
		# Packet will be printed out to the console if there's an error for debugging
		try:
			l2 = rawPacket.summary().split("/")[0].strip()
			l3 = rawPacket.summary().split("/")[1].strip()
			srcIP, dstIP, L7protocol, size, ttl, srcMAC, dstMAC, L4protocol, srcPort, dstPort, payload =\
				"---","---","---","---","---","---","---","---","---","---","---"
			payload = cleanPayload(rawPacket[0].show)
			if rawPacket.haslayer(Ether):
				srcMAC = rawPacket[0][0].src
				dstMAC = rawPacket[0][0].dst
			elif rawPacket.haslayer(Dot3):
				srcMAC = rawPacket[0][0].src
			 	srcIP = rawPacket[0][0].src
			 	dstMAC = rawPacket[0][0].dst
			 	dstIP = rawPacket[0][0].dst
			 	if rawPacket.haslayer(STP):
			 		L7protocol = 'STP'
				 	payload = cleanPayload(rawPacket[STP].show)
			if rawPacket.haslayer(Dot1Q):
				l3 = rawPacket.summary().split("/")[2].strip()
				l4 = rawPacket.summary().split("/")[3].strip().split(" ")[0]
			if rawPacket.haslayer(ARP):
			 	srcMAC = rawPacket[0][0].src
			 	srcIP = rawPacket[0][0].src
			 	dstMAC = rawPacket[0][0].dst
			 	dstIP = rawPacket[0][0].dst
			 	L7protocol = 'ARP'
			 	payload = cleanPayload(rawPacket[0].show)
			# else if rawPacket.haslayer(CDP):
			# 	#dostuff
			#else if rawPacket.haslayer(DHCP):
			# 	#dostuff
			# else if rawPacket.haslayer(DHCPv6):
			# 	#dostuff
			elif (rawPacket.haslayer(IP) or rawPacket.haslayer(IPv6)):
				l4 = rawPacket.summary().split("/")[2].strip().split(" ")[0]
				srcIP = rawPacket[0][l3].src
				dstIP = rawPacket[0][l3].dst
				if l3 == 'IP':
					size = rawPacket[0][l3].len
					ttl = rawPacket[0][l3].ttl
				elif l3 == 'IPv6':
					size = rawPacket[0][l3].plen
					ttl = rawPacket[0][l3].hlim
				L7protocol = rawPacket.lastlayer().summary().split(" ")[0].strip()
				if rawPacket.haslayer(ICMP):
					L7protocol = rawPacket.summary().split("/")[2].strip().split(" ")[0]
					payload = rawPacket[ICMP].summary().split("/")[0][5:]
				if rawPacket.haslayer(TCP):
					srcPort = rawPacket[0][l4].sport
					dstPort = rawPacket[0][l4].dport
					L7protocol = rawPacket.summary().split("/")[2].strip().split(" ")[0]
					L4protocol = rawPacket.summary().split("/")[2].strip().split(" ")[0]
				elif rawPacket.haslayer(UDP):
					srcPort = rawPacket[0][l4].sport
					dstPort = rawPacket[0][l4].dport
					L7protocol = rawPacket.summary().split("/")[2].strip().split(" ")[0]
					L4protocol = rawPacket.summary().split("/")[2].strip().split(" ")[0]
			else:
				srcMAC = "<unknown>"
				dstMAC = "<unknown>"
				l4 = "<unknown>"
				srcIP = "<unknown>"
				dstIP = "<unknown>"
				payload = cleanPayload(rawPacket[0].show)
				
			packet = {'owner': token,\
					"timestamp": str(datetime.now())[:-2],\
					"srcIP": srcIP,\
					"dstIP": dstIP,\
					"L7protocol": L7protocol,\
					"size": size,\
					"ttl": ttl,\
					"srcMAC": srcMAC,\
					"dstMAC": dstMAC,\
					"L4protocol": L4protocol,\
					"srcPort": srcPort,\
					"dstPort": dstPort,\
					"payload": cleanPayload(rawPacket[0].show)\
					}
			# define headers for API POST
			headers = {'content-type': 'application/json'}
			# attempt to jsonify the packet and send to API, if can't jsonify the packet, re-write the payload(this is where json issues would exist)
			try: 	
				r = requests.post(url, data=json.dumps(packet), headers=headers)
			except:
				print "Can't JSONify, POSTing empty payload"
				packet["payload"] = "<unavailable>"
				r = requests.post(url, data=json.dumps(packet), headers=headers)
			return "Packet Uploaded: " + str(packet["timestamp"]) + " ; " + str(packet["srcIP"]) + " ==> " + str(packet["dstIP"] + "; " + str(packet["L4protocol"]))
		except:
			# Debug: if packet error, print out the packet to see what failed
			print cleanPayload(rawPacket[0].show)
			return "Packet Issue, review packet printout for problem"
	
	return parseAndPost

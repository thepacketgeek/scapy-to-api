from scapy.all import *
import requests
import json
from datetime import datetime

## define POST parameters
userToken = ""
url = 'http://localhost:3000/api/packets'
headers = {'content-type': 'application/json'}

# Define optional sniff and packet count
filter = ""
count = 0      # 0 == unlimited

def cleanPayload(p):
	p = str(p)
	# Clean up packet payload from scapy output
	return p.split('Raw')[0].split("Padding")[0].replace('|','\n').strip('<')\
		.strip('bound method Ether.show of ').replace('>','').replace('[<','[')\
		.replace('\n<','<').replace('<','\n')
	
def uploadPacket(a):
	# If we can't parse the packet, we don't want to end the sniffing.
	# Packet will be printed out to the console if there's an error for debugging
	try:
		l2 = a.summary().split("/")[0].strip()
		l3 = a.summary().split("/")[1].strip()
		srcIP, dstIP, L7protocol, size, ttl, srcMAC, dstMAC, L4protocol, srcPort, dstPort, payload =\
			"---","---","---","---","---","---","---","---","---","---","---"
		payload = cleanPayload(a[0].show)
		if a.haslayer(Ether):
			srcMAC = a[0][0].src
			dstMAC = a[0][0].dst
		elif a.haslayer(Dot3):
			srcMAC = a[0][0].src
		 	srcIP = a[0][0].src
		 	dstMAC = a[0][0].dst
		 	dstIP = a[0][0].dst
		 	if a.haslayer(STP):
		 		L7protocol = 'STP'
			 	payload = cleanPayload(a[STP].show)
		if a.haslayer(Dot1Q):
			l3 = a.summary().split("/")[2].strip()
			l4 = a.summary().split("/")[3].strip().split(" ")[0]
		if a.haslayer(ARP):
		 	srcMAC = a[0][0].src
		 	srcIP = a[0][0].src
		 	dstMAC = a[0][0].dst
		 	dstIP = a[0][0].dst
		 	L7protocol = 'ARP'
		 	payload = cleanPayload(a[0].show)
		# else if a.haslayer(CDP):
			# coming soon
		#else if a.haslayer(DHCP):
			# coming soon
		# else if a.haslayer(DHCPv6):
			# coming soon
		elif (a.haslayer(IP) or a.haslayer(IPv6)):
			l4 = a.summary().split("/")[2].strip().split(" ")[0]
			srcIP = a[0][l3].src
			dstIP = a[0][l3].dst
			if l3 == 'IP':
				size = a[0][l3].len
				ttl = a[0][l3].ttl
			elif l3 == 'IPv6':
				size = a[0][l3].plen
				ttl = a[0][l3].hlim
			L7protocol = a.lastlayer().summary().split(" ")[0].strip()
			if a.haslayer(ICMP):
				L7protocol = a.summary().split("/")[2].strip().split(" ")[0]
				payload = a[ICMP].summary().split("/")[0][5:]
			if a.haslayer(TCP):
				srcPort = a[0][l4].sport
				dstPort = a[0][l4].dport
				L7protocol = a.summary().split("/")[2].strip().split(" ")[0]
				L4protocol = a.summary().split("/")[2].strip().split(" ")[0]
			elif a.haslayer(UDP):
				srcPort = a[0][l4].sport
				dstPort = a[0][l4].dport
				L7protocol = a.summary().split("/")[2].strip().split(" ")[0]
				L4protocol = a.summary().split("/")[2].strip().split(" ")[0]
		else:
			srcMAC = "<unknown>"
			dstMAC = "<unknown>"
			l4 = "<unknown>"
			srcIP = "<unknown>"
			dstIP = "<unknown>"
			payload = cleanPayload(a[0].show)
			

		packet = {'owner': userToken,\
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
				"payload": cleanPayload(a[0].show)\
				}
	except:
		# Debug: if packet error, print out the packet to see what failed
		print a
	
	try: 	
		r = requests.post(url, data=json.dumps(packet), headers=headers)
	except:
		packet["payload"] = "<unavailable>"
		r = requests.post(url, data=json.dumps(packet), headers=headers)

	return "Packet Uploaded:", str(packet["timestamp"]), ";", str(packet["srcIP"]), "==>", str(packet["dstIP"])
	
# Start sniffing some packets
sniff(filter=filter, prn=uploadPacket, count=count)
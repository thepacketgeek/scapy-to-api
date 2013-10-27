from scapy.all import *
from meteorshark import uploadPacket
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--count", help="The number of packets to sniff (integer). 0 (default) is indefinite count.")
parser.add_argument("--filter", help="The BPF style filter to sniff with.")
args = parser.parse_args()
if args.count:
	try:
		count = int(args.count)
		print "Sniffing %d packets." % count
	except: 
		print "Count is not a valid integer, using default of 0 (indefinite). Ctrl + C to stop sending packets."
		count = 0
else:
	count = 0
	print "Using default packet count of 0 (indefinite). Ctrl + C to stop sending packets."

if args.filter:
	filter = args.filter
else: 
	filter = ""

## define POST parameters
url = "http://localhost:3000/api/packets"
userToken = ""

# Start sniffing some packets
sniff(filter=filter, prn=uploadPacket(url, userToken), count=count, store=0)
from scapy.all import *
from meteorshark import uploadPacket

## define POST parameters
APIoptions = {"url": "http://localhost:3000/api/packets", "token": ""};

# Define optional sniff and packet count
filter = ""
count = 10      # 0 == unlimited

# Start sniffing some packets
sniff(filter=filter, prn=uploadPacket(APIoptions), count=count)
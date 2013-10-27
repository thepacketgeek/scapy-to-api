# Send packets to a DB via scapy + JSON 

This is a script and module that can run on a computer with the Installation Dependencies listed below. It sniffs packets with Scapy and uploads to a DB w/ API access. I am currently using this along with my [Meteorshark](https://www.github.com/thepacketgeek/meteorshark "Meteorshark") project to easily and quickly show packets for demonstrations which require a more friendly & simpler interface than Wireshark. 

##Usage

Currently both .py files need to be in the same folder but I'm working on an installer so the `meteorshark.py` is available for import globally. You only need to add the 'url' and 'userToken' changes in the `postSniffedPacket.py` script, or copy the script and put it into your own file. 



### Sniffing Packets

Running the `postSniffedPacket.py` with the options object filled out will use scapy to sniff packets (may require root permissions on your system), sending each packet to the meteorshark.uploadPacket() function where they will be parsed and made into a JSON for DB insertion.

### Configuring the API endpoint

You will obviously want to push these packets to some sort of API, otherwise you wouldn't be reading this right now.  To edit the API endpoint, edit these variables towards the top of the script:

url = "http://localhost:3000/api/packets"
userToken = "C0mpl3t1yR@nd0m"

My current API, [Meteorshark](https://www.github.com/thepacketgeek/meteorshark "Meteorshark"), uses a Token instead of authentication right now.  If you need authentication support, feel free to make a pull request as I would love to have that in here as an option!


### Packet Structure

Packets are inserted, stored, and fetched as individual JSON objects in a DB, (I use MongoDB). 

JSON properties are as follows:

<pre><code>packet = {
    "timestamp": "",
	"srcIP": "",
	"dstIP": "",
	"L7protocol": "",
	"size": "",
	"ttl": ""
	"srcMAC": "",
	"dstMAC": "",
	"L4protocol": "",
	"srcPort": "",
	"dstPort": "",
	"payload": "",
	"owner": ""
};
</code></pre>

*Right now, far too much packet protocol support is being done in this client script and I fully plan on figuring out a way to iterate through each field in the packet layers so that I can dump all the important imformation into the DB. This will allow filtering, sorting, and presentation to be completely handled by the server application pulling packet info from the DB.*

### Filtering Packets

Packets can be filtered by scapy while sniffing to limit the amount of packets being sent to the API/DB. Scapy uses the [BPF syntax](http://biot.com/capstats/bpf.html "BPF Syntax") which is also used for Wireshark capture filters. The total number of packets to send can also be configured with the `count` variable.

To add a filter and/or packet count, simply use the CLI '--filter' and '--count' options and enter your values.

Examples:

- `python postSniffedPacket.py --filter="tcp port 80"`
- `python postSniffedPacket.py --filter="host 192.168.200.0/24" --count 10`
- `python postSniffedPacket.py --count 10`

## Installation Dependencies

* [Python 2.7.5+](http://python.org/download/releases/2.7.5/ "Python 2.7.5")
* [Scapy 2.2.0+](http://www.secdev.org/projects/scapy/ "Scapy 2.2.0")
* [Requests 2.0.0+](http://docs.python-requests.org/en/latest/user/install/ "Requests")
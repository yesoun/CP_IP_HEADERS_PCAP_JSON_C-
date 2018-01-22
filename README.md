# CP_IP_HEADERS_PCAP_JSON_C++
Attached Files:
File http.pcap (25.198 KB)
File http.out (39.904 KB)
File tftp_rrq.pcap (30.726 KB)
File tftp_rrq.out (64.618 KB)
Write a program that reads a PCAP file and provides output about that file. This extends assignmetn number 1. 

1. Program will be called from the command line using the source file name as the first command line parameter:

 test> pcap_decode2 <filename>

2. Program will read the pcap file, parsing the main file header, and each packet. See https://wiki.wireshark.org/Development/LibpcapFileFormat for a discussion of the PCAP file format.

 <HINT>   the first example I am giving you (http.pcap) is written by a process using little-endian format for the pcap headers, I use big-endian for data in the TCP and IP headers. Be careful of ethernet MAc address, and IP address orderings. Also, some IPHeader fields are only 4 bits wide. 

3. Program will write out a JSON  format file. Including the following fields (indexed with the strings in the example outputs)

"magicNumber" -- PCAP magic number
"majorVersion"   -- PCAP file major version number
"minorVersion" -- PCAP minor version number
"thisZone" -- PCAP time zone (GMT to local correction)
"sigFigs" -- accuracy of timestamps
"snapLen" -- maximum packet size
"network" -- data link type
"count" -- total number of packets read in this file. Your program will have to calculate this
and for each packet

 a packet number, starting at 0 (See posted format)
"tmSec" -- timestamp seconds
"tmUSec" -- timestamp microseconds
"inclLen" -- number of octets/bytes of packet in the pcap file
"origLen" -- number of octets/byets of packet on the network (will be same as inclLen unless bigger than snapLen

Sample output format attached: (newlines don't matter here. Also, order of fields in {...}  don't matter. 

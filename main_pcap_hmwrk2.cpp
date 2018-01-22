/**

Author: Yassine Maalej                  Email: maal4948@vandals.uidaho.edu  Email: maalej.yessine@gmail.com
Class: Network Security CS 538
Assignment2: reading the header the file and parsing the main header file and every packet header.

The output of corresponding to the global header is the same as the one shown in the first homework:
Just here reorganized in the same ordering that you gave to us in the two output files http.out and tftp_rqq.out
{
--------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------
"count" -- total number of packets read in this file. Your program will have to calculate this
"magicNumber" -- PCAP magic number
"majorVersion"   -- PCAP file major version number
"minorVersion" -- PCAP minor version number
"network" -- data link type
"sigFigs" -- accuracy of timestamps
"snapLen" -- maximum packet size
"thisZone" -- PCAP time zone (GMT to local correction)
--------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------

and then for each packet we give its details with brackets
--------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------
 a packet number, starting at 0 (See posted format)
"tmSec" -- timestamp seconds
"tmUSec" -- timestamp microseconds
"inclLen" -- number of octets/bytes of packet in the pcap file
"origLen" -- number of octets/byets of packet on the network (will be same as inclLen unless bigger than snapLen
--------------------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------------------


Different from hmwrk1, only the data or info in the TCP and IP header files are written using big endian.

Online References for help:
http://www.scs.ryerson.ca/~zereneh/linux/PacketReading.pdf
http://www.tcpdump.org/pcap.html

*/

#include <iostream>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <asm/types.h>
#include <stdlib.h>
#include <cstring>
typedef __u32  guint32;
typedef __u16  guint16;
typedef   int   gint32;


using namespace std;

/**This header starts with the libpcap Global Header (that is 24 octets long)
    and will be followed by the first packet header and has the following structure*/
typedef struct pcap_hdr_s {
	guint32 magic_number;   /* magic number -                             > 4 octet */
	guint16 version_major;  /* major version number                       > 2 octet */
	guint16 version_minor;  /* minor version number                       > 2 octet */
	gint32  thiszone;       /* GMT to local correction                    > 2 octet +2 padding*/
	guint32 sigfigs;        /* accuracy of timestamps                     > 4 octet */
	guint32 snaplen;        /* max length of captured packets, in octets  > 4 octet */
	guint32 network;        /* data link type                             > 4 octet */
} pcap_hdr_t;

/** Each captured packet starts with (any byte alignment possible):
    the size of the structure holding each packet header (that is 16 octect long)
*/
typedef struct pcaprec_hdr_s {
	guint32 ts_sec;         /* timestamp seconds                          > 4 octet */
	guint32 ts_usec;        /* timestamp microseconds                     > 4 octet */
	guint32 incl_len;       /* number of octets of packet saved in file   > 4 octet */
	guint32 orig_len;       /* actual length of packet                    > 4 octet*/


} pcaprec_hdr_t;

/** used to print binaries for me to check how to shift and masks to use*/
void print_bits(unsigned int x)
{
    int i;
    for(i=8*sizeof(x)-1; i>=0; i--) {
        (x & (1 << i)) ? putchar('1') : putchar('0');
    }
    printf("\n");
}



int main(int argc, char const* argv[])
{
    // if no pcap file is given after the executable main_pcap_json.o then return 1
	if (argc != 2) {
		printf("NO PCAP FILE IS GIVEN AFTER ./main_hmwrk_2.o %s", argv[0]);
		return 1;
	}

    // else we open the PCAP file in read only mode since in this assignemnet we do not have to write anything.
	int fd = open(argv[1], O_RDONLY);
	if (fd == -1) {
		cout<<"ERROR OPENING PCAP FILE"<< endl;
        return 1;
	}

    // the size of the guint32 is 4* (8bit) octect
    //cout<< "sizeofguint32"<< sizeof(guint32)<<endl;

    // the size of the guint16 is 2* (8bit) octect
    //cout<< "sizeofguint16"<< sizeof(guint16)<<endl;


    // the size of the gint16 is 2* (8bit) octect
    //cout<< "sizeofgint16"<< sizeof(guint16)<<endl;


    // 24 octect the sizeof(pcap_hdr_t), which mean
    int pcap_hdr_l = sizeof(pcap_hdr_t);
	//cout<< "pcap_hdr_l " << pcap_hdr_l << endl;

	pcap_hdr_t *pcap_header = (pcap_hdr_t *)malloc(pcap_hdr_l);

	int hdr_l = read(fd, pcap_header, pcap_hdr_l);

	int pcap_pkthdr_l = sizeof(pcaprec_hdr_t);
	//cout<< "sizeof(pcaprec_hdr_t)" << sizeof(pcaprec_hdr_t)<<endl;

	pcaprec_hdr_t *pcap_pktheader = (pcaprec_hdr_t *)malloc(pcap_pkthdr_l);

    // total number of packets
    int countPackets=0;
    // first bracket
    printf("{ \n");
    //going throught the packet headers
    while (true){
        void *pkt = malloc(pcap_pktheader->incl_len);
        int pkthdr_l = read(fd, pcap_pktheader, pcap_pkthdr_l);
        int pkt_l = read(fd, pkt, pcap_pktheader->incl_len);
        if (pkt_l != pcap_pktheader->orig_len) {
            break; // if the packet
        }
        printf("\"%d\": \{",countPackets);
        int i;
	    int h = 0;
        /** ethernet header with  "dst": "fe::ff::20::00::01::00",
            "src": "00::00::01::00::00::00",
            "type": "0x0800"
            **/
        printf("\n    \"ethHdr\": {\n");
        printf("        \"dst\": \"%02x::%02x::%02x::%02x::%02x::%02x\", \n", *((unsigned char *) pkt + 0), *((unsigned char *) pkt + 1), \
              *((unsigned char *) pkt + 2), *((unsigned char *) pkt + 3), *((unsigned char *) pkt + 4), *((unsigned char *) pkt + 5) );
        printf("        \"src\": \"%02x::%02x::%02x::%02x::%02x::%02x\", \n", *((unsigned char *) pkt + 6), *((unsigned char *) pkt + 7), \
              *((unsigned char *) pkt + 8), *((unsigned char *) pkt + 9), *((unsigned char *) pkt + 10), *((unsigned char *) pkt + 11) );
        printf("        \"type\": \"0x%02x%02x\" \n", *((unsigned char *) pkt + 12), *((unsigned char *) pkt + 13));
        printf("    },");
        /** "incLen": 62, return line */
        printf("\n    \"incLen\": %d,\n", pcap_pktheader->incl_len);
        /**
        "ip4Hdr": {
            "checksum": "0x91eb",
            "dst": "65.208.228.223",
            "flags": "0x2",
            "fragmentOffset": 0,
            "headerLen": 5,
            "protocol": 6,
            "src": "145.254.160.237",
            "timeToLive": 128,
            "totalId": 3905,
            "totalLen": 48,
            "typeOfService": 0,
            "version": 4
        },
        */
        printf("    \"ip4Hdr\": {\n");
        printf("        \"checksum\": \"0x%02x%02x\", \n", *((unsigned char *) pkt + 24), *((unsigned char *) pkt + 25));
        printf("        \"dst\": \"%d.%d.%d.%d\", \n", *((unsigned char *) pkt + 30), *((unsigned char *) pkt + 31), *((unsigned char *) pkt + 32), *((unsigned char *) pkt + 33) );




        /**
        flags: bits 16 17 18 in the of the 7th and 8th byte, only 3 bits >>5
        Fragment offset: from bit 19 to 31 of the 7th and 8th byte,
        */
        unsigned int byte7_8= (*((unsigned char *) pkt + 20)<<8) | (*((unsigned char *) pkt + 21)) ;
        //print_bits(byte7_8);

        //unsigned int flags = byte7_8 >> 13;
        //flags = byte7_8 &0x7;

        unsigned int flags=(*((unsigned char *) pkt + 20));
       // print_bits(flags);
        flags = flags >> 5;
        printf("        \"flags\": \"0x%d\", \n", flags);  // not yet working

        unsigned int fragmentOffset = byte7_8 >>3;
        //print_bits(fragmentOffset);
        fragmentOffset = byte7_8 & 0x1FFF;
        printf("        \"fragmentOffset\": \"%d\", \n", fragmentOffset);  // not yet working

        /** header length 4th last bits in the first byte */
        unsigned int headerLen= *((unsigned char *) pkt + 14);
        headerLen = headerLen & 0xF;
        printf("        \"headerLen\": \"%d\", \n", headerLen);

        printf("        \"protocol\": \"%d\", \n", *((unsigned char *) pkt + 23));

        printf("        \"src\": \"%d.%d.%d.%d\", \n", *((unsigned char *) pkt + 26), *((unsigned char *) pkt + 27), *((unsigned char *) pkt + 28), *((unsigned char *) pkt + 29) );

        printf("        \"timeToLive\": \"%d\", \n", *((unsigned char *) pkt + 22));
        // total id spans on 2 bytes
        unsigned int tot_id= (*((unsigned char *) pkt + 18)<<8) | (*((unsigned char *) pkt + 19)) ;
        printf("        \"totalId\": \"%d\", \n", tot_id);
        printf("        \"totalLen\": \"%d\", \n", *((unsigned char *) pkt + 17));

        printf("        \"typeOfService\": \"%d\", \n", *((unsigned char *) pkt + 15));

        /** 4th first bits in the first byte */
        unsigned int version= *((unsigned char *) pkt + 14);
        version = version >> 4;
        version = version & 0xF;
        printf("        \"version\": \"%d\", \n", version);
        printf("    },\n")     ;

        /**"origLen": 62,*/
        printf("    \"origLen\": %d, ", pcap_pktheader->orig_len);

        /**
        "tcpHdr": {
            "ackNum": 0,
            "checksum": 49932,
            "dstPort": 80,
            "flags": 2,
            "offset": 7,
            "seqNum": 951057939,
            "srcPort": 3372,
            "urgentPtr": 0,
            "window": 8760
        },
        */
        printf("\n    \"tcpHdr\": {\n");

        unsigned int ackNum= (*((unsigned char *) pkt + 42)<<24) | (*((unsigned char *) pkt + 43)<<16) | \
                             (*((unsigned char *) pkt + 44)<<8) | (*((unsigned char *) pkt + 45)) ;
        printf("        \"ackNum\": \"%d\", \n", ackNum);        // not yet working

        unsigned int check_sm= (*((unsigned char *) pkt + 50)<<8) | (*((unsigned char *) pkt + 51)) ;
        printf("        \"checksum\": \"%d\", \n", check_sm);

        unsigned int dst_port= (*((unsigned char *) pkt + 36)<<8) | (*((unsigned char *) pkt + 37)) ;
        printf("        \"dstPort\": \"%d\", \n", dst_port);
        printf("        \"flags\": \"%d\", \n", *((unsigned char *) pkt + 47));



        /** we only need to take the first bits from 0-3 in the the 46th byte */
        unsigned int off_decimal= *((unsigned char *) pkt + 46);
        //print_bits(off_decimal);
        off_decimal = off_decimal >> 4;
        unsigned int offset = off_decimal & 0xF;
        //print_bits(off_decimal);
        //print_bits(offset);
        printf("        \"offset\": \"%d\", \n", offset);


        unsigned int seqNum= (*((unsigned char *) pkt + 38)<<24) | (*((unsigned char *) pkt + 39)<<16) | \
                             (*((unsigned char *) pkt + 40)<<8) | (*((unsigned char *) pkt + 41)) ;
        printf("        \"seqNum\": \"%d\", \n", seqNum);

        unsigned int src_port= (*((unsigned char *) pkt + 34)<<8) | (*((unsigned char *) pkt + 35)) ;
        printf("        \"srcPort\": \"%d\", \n", src_port);


        unsigned int urgentPtr= (*((unsigned char *) pkt + 52)<<8) | (*((unsigned char *) pkt + 53)) ;
        printf("        \"urgentPtr\": \"%d\", \n", urgentPtr);


        unsigned int window= (*((unsigned char *) pkt + 48)<<8) | (*((unsigned char *) pkt + 49)) ;
        printf("        \"window\": \"%d\", \n", window);
        printf("    },");
        /** and finally
            "tmSec": 1084443427,
            "tmUSec": 311224
        */
        printf("\n    \"tmSec\": %d, ", pcap_pktheader->ts_sec);
        printf("\n    \"tmUSec\": %d \n ", pcap_pktheader->ts_usec);

        /** end of printing details of the packet */
        printf("},\n");
        countPackets +=1;

    }
    // the total number of packets
    int totalNumberPackets=countPackets;

	/** beginninjg of typing of the main file header*/
    printf("\"count\": %d, \n",        totalNumberPackets);
	printf("\"magicNumber\": %u, \n",  pcap_header->magic_number);
	printf("\"majorVersion\": %d, \n", pcap_header->version_major);
	printf("\"minorVersion\": %d, \n", pcap_header->version_minor);
	printf("\"network\": %d, \n",      pcap_header->network);
	printf("\"sigFigs\": %d, \n",      pcap_header->version_minor);
	printf("\"snaplen\": %d, \n",      pcap_header->snaplen);
	printf("\"thiszone\": %d \n",      pcap_header->thiszone);

    // ending bracket
    cout<< "}"<<endl;
	close(fd);
	return 0;
}


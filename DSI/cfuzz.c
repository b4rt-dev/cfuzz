/*
This is the main file. It handles sending, receiving, but also monitoring of frames.
*/
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include "cfuzz.h"
#include "frameCreator.h"
#include "frameDefinitions.h"
#include "fuzzer.h"

#define DEBUG (0)
#define SUTTIMEOUTMS (30000) //30s

//Used for timing
struct timeval tm1;
struct timeval longtm;

//Number of acked frames in current step
int ackedFrames             = 0;

//Copied from Wireshark
u_char radioTapHeader[36]   =   "\x00\x00\x24\x00\x2f\x40\x00\xa0\x20\x08\x00\x00\x00\x00\x00\x00" \
                                "\x9d\x5c\xa0\x15\x01\x00\x00\x00\x10\x02\x6c\x09\xa0\x00\xa7\x00" \
                                "\x00\x00\xa7\x00";

//Mac address of Atheros Wi-Fi dongle
//Dongle will only ACK frames to its own MAC address
u_char myMAC[6]            =  "\x00\x0a\xeb\x2d\x72\x55";

//Mac address of SUT
//Is needed to ignore frames from other devices
/*List of MACs for test devices:
- d0:17:6a:e8:e9:7a Samsung Galaxy Ace
- xx:xx:xx:xx:xx:xx Chromecast 1
- ec:9b:f3:1e:19:71 Samsung Galaxy S6
- cc:fa:00:c9:fc:ad LG Optimus G
- 12:42:2a:7e:d4:e8 Orange Pi Zero
*/
//Comment out the SUT
//u_char sutMAC[6]            =  "\xec\x9b\xf3\x1e\x19\x71"; //Galaxy S6
//u_char sutMAC[6]            =  "\xcc\xfa\x00\xc9\xfc\xad"; //LG Optimus G
//u_char sutMAC[6]            =  "\xd0\x17\x6a\xe8\xe9\x7a"; //Galaxy Ace
//u_char sutMAC[6]            =  "\x12\x42\x2a\x7e\xd4\xe8"; //Orange Pi Zero
//u_char sutMAC[6]            =  "\xe0\xe7\x51\x45\x5e\x5d"; //DSI XL
u_char sutMAC[6]            =  "\xe0\xe7\x51\x45\x5e\x5d"; //DSI XL


//Returns filter for libpcap
//we want to use as many filters here as possible, since libpcap is closer to the hardware than this user-level program
//we only want to receive Probe requests, Authentication frames and Association requests, all to only our own MAC address or broadcast address in case of Probe requests
//furthermore, all frames except ACK frames (have no send address) should be sent from the SUT MAC address
//also, it is important not to compile and set the filter between each pcap_next. Otherwise ACK frames will be missed
//when changing the filterString, the strncpy() locations should also be changed!
const char *getFilterString()
{
    static char filterString[] = "wlan addr2 e0:e7:51:45:5e:5d";

    return filterString;
}

//Starts timer by setting current (starting) time to tm1
void startTimer()
{
    gettimeofday(&tm1, NULL);
}

//Stops timer by setting current (ending) time to tm2
//Then compares difference in time and returns it in milliseconds
unsigned long long stopTimer()
{
    struct timeval tm2;
    gettimeofday(&tm2, NULL);

    unsigned long long t = 1000 * (tm2.tv_sec - tm1.tv_sec) + (tm2.tv_usec - tm1.tv_usec) / 1000;
    return t;
}

//Starts timer by setting current (starting) time to longtm
//Longtimer is used to determine if it was more than X seconds since the SUT sent out frames
void startLongTimer()
{
    gettimeofday(&longtm, NULL);
}

//Stops timer by setting current (ending) time to longtm2
//Then compares difference in time and returns it in milliseconds
unsigned long long stopLongTimer()
{
    struct timeval longtm2;
    gettimeofday(&longtm2, NULL);

    unsigned long long t = 1000 * (longtm2.tv_sec - longtm.tv_sec) + (longtm2.tv_usec - longtm.tv_usec) / 1000;
    return t;
}

//Returns source address pointer location in packet
u_char *getSourceAddrOfPacket(const u_char *packet)
{
    //get header length
    u_char headerLength;
    headerLength = packet[2];

    //calculate offset to address
    const u_char *addr;
    int offset = headerLength;
    offset = offset + 10;

    //get pointer to address
    addr = packet + offset;

    return (u_char*) addr;
}

//Returns Version, Type and Subtype (one byte)
u_char getFrameTypeOfPacket(const u_char *packet)
{
    //get header length
    u_char headerLength;
    headerLength = packet[2];

    //calculate offset to frame type
    const u_char *frameType;
    int offset = headerLength;
    offset = offset + 0;

    //get pointer to frameType
    frameType = packet + offset;

    return *frameType;
}

//Sends packet using pcap. Returns status
int sendPacket(pcap_t *pcap_h, u_char *packet, int size)
{
    int sendStatus = pcap_sendpacket(pcap_h, packet, size);

    //when frame failed to send
    if (sendStatus == 1)
    {
        printf("Failed to send frame:\n");
        //print failed frame
        int printCounter = 0;
        for(int i = 0; i < size; i++)
        {
            printf("%02X ", packet[i]);
            printCounter = printCounter + 1;
            if (printCounter == 16)
            {
                printCounter = 0;
                printf("\n");
            }
        }
        printf("\n");
    }
    
    return sendStatus;
}

int main(int argc, char *argv[])
{
    pcap_t  *pcap_h;
    struct  bpf_program fp;
    struct  pcap_pkthdr header;
    char    *dev;
    char    errbuf[PCAP_ERRBUF_SIZE];

    //check argument number
    if(argc != 2)
    {
        printf("Usage: %s device\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    dev = argv[1];

    //initialize libpcap
    if((pcap_h = pcap_create(dev, errbuf)) == NULL)
    {
         printf("pcap_create() failed: %s\n", errbuf);
         exit(EXIT_FAILURE);
    }

    if(pcap_can_set_rfmon(pcap_h) == 0)
    {
        printf("Monitor mode can not be set.\n");
        exit(EXIT_FAILURE);
    }

    if(pcap_set_rfmon(pcap_h, 1) != 0)
    {
        printf("Failed to set monitor mode.\n");
        exit(EXIT_FAILURE);
    }

    if(pcap_activate(pcap_h) != 0)
    {
        printf("pcap_activate() failed\n");
        exit(EXIT_FAILURE);
    }

    //compile filter for incoming packets
    if(pcap_compile(pcap_h, &fp, getFilterString() , 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        printf("failed pcap_compile() with error: %s\n", pcap_geterr(pcap_h));
        exit(EXIT_FAILURE);
    }

    //apply filter
    if(pcap_setfilter(pcap_h, &fp) == -1)
    {
        printf("failed pcap_setfilter() with error: %s\n", pcap_geterr(pcap_h));
        exit(EXIT_FAILURE);
    }

    //free memory allocated by pcap_compile()
    pcap_freecode(&fp);

    //flag to indicate if we have to listen for ACK verification
    int waitForACK = 0;

    //counter for continuous ACK fail
    int noACKcounter = 0;

    //start long timer
    startLongTimer();

    //infinite listen-respond loop
    while (1)
    {
        //receive packet
        const u_char *rpacket = pcap_next(pcap_h, &header);

        printf("Received Frame\n");

        int packetSize;
        u_char *packet = createProbeResponse(sutMAC, &packetSize, radioTapHeader, myMAC);
        sendPacket(pcap_h, packet, packetSize);
        free(packet);      //free allocated memory

        printf("Sent frame:\n");
        //print failed frame
        int printCounter = 0;
        for(int i = 0; i < packetSize; i++)
        {
            printf("%02X ", packet[i]);
            printCounter = printCounter + 1;
            if (printCounter == 16)
            {
                printCounter = 0;
                printf("\n");
            }
        }
        printf("\n");

        increaseFuzzer();

        
        
    }

    return 0;
}
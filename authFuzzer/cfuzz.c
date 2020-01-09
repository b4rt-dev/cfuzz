/*
This is the main file. It handles sending, receiving, but also monitoring of frames.
*/
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include "cfuzz.h"
#include "frameCreator.h"
#include "frameDefinitions.h"
#include "fuzzer.h"

#define DEBUG (0)
#define SUTTIMEOUTMS (30000) //30s
#define SENDDISASS (1) //send dissassociation frame after association

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
//Comment out the SUT
u_char sutMAC[6]            =  "\xec\x9b\xf3\x1e\x19\x71"; //Galaxy S6
//u_char sutMAC[6]            =  "\xcc\xfa\x00\xc9\xfc\xad"; //LG Optimus G
//u_char sutMAC[6]            =  "\xd0\x17\x6a\xe8\xe9\x7a"; //Galaxy Ace
//u_char sutMAC[6]            =  "\x12\x42\x2a\x7e\xd4\xe8"; //Orange Pi Zero
//u_char sutMAC[6]            =  "\x00\x09\xbf\x7d\x6d\xaa"; //Nintendo DS
//u_char sutMAC[6]            =  "\x00\x01\x4a\x93\xce\x34"; //PSP
//u_char sutMAC[6]            =  "\xe0\xe7\x51\x45\x5e\x5d"; //DSI
//u_char sutMAC[6]            =  "\x9c\xe6\x35\x2a\x69\x16"; //WII U
//u_char sutMAC[6]            =  "\x6c\xad\xf8\xc8\x77\xca"; //Chromecast 1
//u_char sutMAC[6]            = "\xb8\x27\xeb\xf1\x89\x68"; //RPI 3
//u_char sutMAC[6]            = "\x84\x00\xd2\xe0\x81\xb2"; //Xperia Ray
//u_char sutMAC[6]            = "\x54\x60\x09\xf8\xbe\x28"; //Chromecast Audio
//u_char sutMAC[6]            = "\x80\x7d\x3a\x73\x81\xc7"; //Power plug

//Returns filter for libpcap
//we want to use as many filters here as possible, since libpcap is closer to the hardware than this user-level program
//we only want to receive Probe requests, Authentication frames and Association requests, all to only our own MAC address or broadcast address in case of Probe requests
//furthermore, all frames except ACK frames (have no send address) should be sent from the SUT MAC address
//also, it is important not to compile and set the filter between each pcap_next. Otherwise ACK frames will be missed
//when changing the filterString, the strncpy() locations should also be changed!
const char *getFilterString()
{
    //xx:xx:xx:xx:xx:xx will become myMAC, yy:yy:yy:yy:yy:yy will become sutMAC
    static char filterString[] = "(wlan subtype probe-req and (wlan addr1 xx:xx:xx:xx:xx:xx or wlan addr1 ff:ff:ff:ff:ff:ff) and wlan addr2 yy:yy:yy:yy:yy:yy)" \
    " or ( wlan addr1 xx:xx:xx:xx:xx:xx and wlan addr2 yy:yy:yy:yy:yy:yy and ( wlan subtype auth or wlan subtype assoc-req))" \
    " or ( wlan addr1 xx:xx:xx:xx:xx:xx and wlan subtype ack)";

    //convert myMAC and sutMAC to strings
    char myMacStr[18];
    char sutMacStr[18];

    snprintf(myMacStr, sizeof(myMacStr), "%02x:%02x:%02x:%02x:%02x:%02x",
             myMAC[0], myMAC[1], myMAC[2], myMAC[3], myMAC[4], myMAC[5]);

    snprintf(sutMacStr, sizeof(sutMacStr), "%02x:%02x:%02x:%02x:%02x:%02x",
             sutMAC[0], sutMAC[1], sutMAC[2], sutMAC[3], sutMAC[4], sutMAC[5]);

    //replace placeholder MACs in filterString with correct MACstring (hardcoded positions!)
    strncpy(filterString+40, myMacStr,17);
    strncpy(filterString+106, sutMacStr,17);
    strncpy(filterString+141, myMacStr,17);
    strncpy(filterString+174, sutMacStr,17);
    strncpy(filterString+260, myMacStr,17);

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

    //initialize the fuzzer
    increaseFuzzer(); 

    //start long timer
    startLongTimer();

    //infinite listen-respond loop
    while (1)
    {
        //receive packet
        const u_char *packet = pcap_next(pcap_h, &header);

        unsigned long long LongtimeSincePrevPacket = stopLongTimer();

        if (LongtimeSincePrevPacket > SUTTIMEOUTMS)
        {
            printf("\e[31mIt took %llu ms to receive any frame from the SUT. Possible crash?\e[39m\n", LongtimeSincePrevPacket);
        }

        startLongTimer();

        unsigned long long timeSincePrevPacket = stopTimer();

        u_char frameType = getFrameTypeOfPacket(packet);

        u_char* sourceAddr;


        if (frameType != 0xd4) //ACK frames have no source address
            sourceAddr = getSourceAddrOfPacket(packet);

        //if we had to wait for an ACK, verify if current frame is an ACK
        if (waitForACK != 0)
        {
            //printf("Received frame of type %d\n", frameType);
            if (stopTimer() <= 30)
            {
                if (frameType == 0xd4)
                {
                    //printf("ACKed\n");
                    if (DEBUG)
                    {
                        switch (waitForACK)
                        {
                            case 1:
                            {
                                printf("Association response ACKed\n");
                                break;
                            }
                            case 2:
                            {
                                printf("Authentication frame ACKed\n");
                                break;
                            }
                            case 3:
                            {
                                printf("Probe response ACKed\n");
                                break;
                            }
                            default:
                            {
                                printf("Frame ACKed\n");
                                break;
                            }
                        }
                    }
                    //if ACK was on Ass resp frame, only then increase fuzzer
                    if (waitForACK == 1)
                    {
                        //disassociate if specified
                        if (SENDDISASS == 1)
                        {
                            sleep(1);
                            int packetSize;
                            u_char *packet = createDisAss(sutMAC, &packetSize, radioTapHeader, myMAC);
                            sendPacket(pcap_h, packet, packetSize);
                            free(packet);      //free allocated memory
                            packet = createDisAss(sutMAC, &packetSize, radioTapHeader, myMAC);
                            sendPacket(pcap_h, packet, packetSize);
                            free(packet);      //free allocated memory
                            //sleep(1);
                            /*packet = createDisAss(sutMAC, &packetSize, radioTapHeader, myMAC);
                            sendPacket(pcap_h, packet, packetSize);
                            free(packet);      //free allocated memory
                            packet = createDisAss(sutMAC, &packetSize, radioTapHeader, myMAC);
                            sendPacket(pcap_h, packet, packetSize);
                            free(packet);      //free allocated memory
                            packet = createDisAss(sutMAC, &packetSize, radioTapHeader, myMAC);
                            sendPacket(pcap_h, packet, packetSize);
                            free(packet);      //free allocated memory*/
                        }
                        
                    }
                    if (waitForACK == 2)
                    {
                        increaseFuzzer();               //fuzz next thing
                    }

                    ackedFrames = ackedFrames + 1;  //the frame is acked, so increase counter
                    waitForACK = 0;                 //we should stop waiting for ack and move on
                    noACKcounter = 0;               //reset counter
                    

                    if (DEBUG)
                    {
                        //printf("Frame ACKed, fuzzStep is now %d\n", getFuzzStep());
                        printf("Frame ACKed\n");
                    }
                    
                }
                else //received other frame. Ignore and keep listening
                {
                    if (DEBUG)
                    {
                        printf("Got other frame. Will be ignored\n");   
                    }
                }    
            }
            else //waited more than 10 ms for ack. failed
            {
                //printf("Did not capture an ACK in time\n");
                noACKcounter = noACKcounter + 1;
                if (noACKcounter == 5)
                {
                    printf("\e[31mFrame not ACKed after 5 retries, moving on\e[39m\n");
                    noACKcounter = 0;
                    increaseFuzzer();
                }
                if (DEBUG)
                {
                    printf("Not sure if frame was ACKed\n");
                }
                waitForACK = 0;
            }
        }
        else //Process frame depending on type
        {
            switch(frameType)
            {
                case 0x40:
                {
                    int packetSize;
                    u_char *packet = createProbeResponse(sourceAddr, &packetSize, radioTapHeader, myMAC);
                    sendPacket(pcap_h, packet, packetSize);
                    free(packet);      //free allocated memory
                    waitForACK = 0;
                    startTimer();
                    break;
                } 
                case 0xb0:
                {
                    int packetSize;
                    u_char *packet = createAuthResponse(sourceAddr, &packetSize, radioTapHeader, myMAC);
                    sendPacket(pcap_h, packet, packetSize);
                    free(packet);      //free allocated memory
                    waitForACK = 2;
                    startTimer();
                    break;
                }
                case 0x00:
                {
                    int packetSize;
                    u_char *packet = createAssResponse(sourceAddr, &packetSize, radioTapHeader, myMAC);
                    sendPacket(pcap_h, packet, packetSize);
                    free(packet);      //free allocated memory
                    waitForACK = 1;
                    startTimer();
                    break;
                }
                case 0xd4:
                {
                    break;
                }
                default: break;
            }
        }
        
    }

    return 0;
}
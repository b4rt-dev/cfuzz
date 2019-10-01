/*
NOTES:
- Only tested with Atheros AR9271 USB dongle
- Frames are being ACKed by the firmware as long as the MAC address is correct
- Frames are being retransmitted by the firmware when there is no ACK response (except beacon frames IIRC)

*/

#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h> 
#include "cfuzz.h"
#include <sys/time.h>

#define DEBUG (0)

//Used for timing
struct timeval tm1;

//Current (initial) state and step of the fuzzer
unsigned long fuzzState     = 0;
unsigned long fuzzStep      = 0;

//Number of acked frames in current step
int ackedFrames             = 0;

//Copied from wireshark. Will be overwritten by firmware
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
*/
//Comment out the SUT
//u_char sutMAC[6]            =  "\xec\x9b\xf3\x1e\x19\x71"; //Galaxy S6
u_char sutMAC[6]            =  "\xcc\xfa\x00\xc9\xfc\xad"; //LG Optimus G
//u_char sutMAC[6]            =  "\xd0\x17\x6a\xe8\xe9\x7a"; //Galaxy Ace

//Returns filter for libpcap
//we want to use as many filters here as possible, since libpcap is closer to the hardware than this user-level program
//we only want to receive Probe requests, Authentication frames and Association requests, all to only our own MAC address or broadcast address
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

int states[] = {0,1,2,3};
int steps[] = {45,45,16,256};

//Controls state of fuzzer, and therefore what to fuzz next
void increaseFuzzer()
{
    if (fuzzState >= 4)
    {
        printf("Done with Fuzzing\n");
        exit(0);
    }
    else
    {
        if (fuzzStep == 0)
        {
            switch (fuzzState)
            {
                case 0: 
                {
                    printf("Fuzzing SSID incorrect length with data\n");
                    break;
                }
                case 1: 
                {
                    printf("Fuzzing SSID incorrect length without data\n");
                    break;
                }
                case 2: 
                {
                    printf("Fuzzing SSID oversized length\n");
                    break;
                }
                case 3: 
                {
                    printf("Fuzzing SSID characters\n");
                    break;
                }
            }
        }
        if (fuzzStep < steps[fuzzState])
            fuzzStep = fuzzStep + 1;
        else
        {
            fuzzStep = 0;
            fuzzState = fuzzState + 1;
        }
    }

}

infoElem ssidFuzz()
{
    infoElem ssid = {
            0,         //id
            4,         //len
            4,         //real length of data
            "\x46\x55\x5a\x5a" //data
            };

    switch (fuzzState)
    {
        case 0: //SSID incorrect length with data
        {
            if (fuzzStep <= 38)
            {
                ssid.id = 0;
                ssid.len = fuzzStep;
                ssid.len_data = 4;
                ssid.data = "\x46\x55\x5a\x5a";
            }
            else
            {
                ssid.id = 0;
                ssid.len = 255 - (fuzzStep - 39);
                ssid.len_data = 4;
                ssid.data = "\x46\x55\x5a\x5a";
            }
            break;
        }
        case 1: //SSID incorrect length without data
        {
            if (fuzzStep <= 38)
            {
                ssid.id = 0;
                ssid.len = fuzzStep;
                ssid.len_data = 0;
                ssid.data = "";
            }
            else
            {
                ssid.id = 0;
                ssid.len = 255 - (fuzzStep - 39);
                ssid.len_data = 0;
                ssid.data = "";
            }
            break;
        }
        case 2: //SSID oversized length
        {
            if (fuzzStep < 8)
            {
                int dataSize = 33 + fuzzStep;

                ssid.id = 0;
                ssid.len = dataSize;
                ssid.len_data = dataSize;
                //create data of datasize times 0x61
                u_char *data = malloc(dataSize);
                memset(data, 0x61, dataSize);
                ssid.data = data;
            }
            else
            {
                int dataSize = 255 - fuzzStep;

                ssid.id = 0;
                ssid.len = dataSize;
                ssid.len_data = dataSize;
                //create data of datasize times 0x61
                u_char *data = malloc(dataSize);
                memset(data, 0x61, dataSize);
                ssid.data = data;
            }
            break;
        }
        case 3:  //SSID characters
        {
            ssid.id = 0;
            ssid.len = 32;
            ssid.len_data = 32;
            //create characters
            u_char *data = malloc(32);
            for (int i = 0; i < 32; i++)
            {
                data[i] = fuzzStep;
            }
            ssid.data = data;
            break;
        }

        
    }
    

    return ssid;
}

//Places source address from packet in addrArray
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

//Creates Authentication Response frame and sends it
int sendAuthResponse(pcap_t *pcap_h, u_char *dstAddress)
{
    //fill in struct
    authResponse authResp = { 
        36, radioTapHeader,                //RadioTap hdr   (overwritten by firmware)
        1, "\xb0",                         //Type
        1, "\x00",                         //Subtype
        2, "\x3a\x01",                     //Duration
        6, dstAddress,                     //DST addr
        6, myMAC,                          //Source addr
        6, myMAC,                          //BSS addr
        2, "\x00\x00",                     //Seq nr         (overwritten by firmware)
        2, "\x00\x00",                     //Auth alg
        2, "\x02\x00",                     //Auth seq
        2, "\x00\x00",                     //Status code
        4, "\x00\x00\x00\x00"              //FSC            (overwritten by firmware)
    };

    //calculate size of final packet
    int packetSize = authResp.len_radioTapHdr 
                + authResp.len_type
                + authResp.len_flags
                + authResp.len_duration
                + authResp.len_destAddr
                + authResp.len_sourceAddr
                + authResp.len_bssAddr
                + authResp.len_seqNr
                + authResp.len_authAlg
                + authResp.len_authSeq
                + authResp.len_status
                + authResp.len_fsc;

    //define packet
    u_char authRespPacket[packetSize];


    //copy all struct fields into packet
    int copyOffset = 0;

    memcpy(authRespPacket + copyOffset, authResp.radioTapHdr, authResp.len_radioTapHdr);
    copyOffset = copyOffset + authResp.len_radioTapHdr;

    memcpy(authRespPacket + copyOffset, authResp.type, authResp.len_type);
    copyOffset = copyOffset + authResp.len_type;

    memcpy(authRespPacket + copyOffset, authResp.flags, authResp.len_flags);
    copyOffset = copyOffset + authResp.len_flags;

    memcpy(authRespPacket + copyOffset, authResp.duration, authResp.len_duration);
    copyOffset = copyOffset + authResp.len_duration;

    memcpy(authRespPacket + copyOffset, authResp.destAddr, authResp.len_destAddr);
    copyOffset = copyOffset + authResp.len_destAddr;

    memcpy(authRespPacket + copyOffset, authResp.sourceAddr, authResp.len_sourceAddr);
    copyOffset = copyOffset + authResp.len_sourceAddr;

    memcpy(authRespPacket + copyOffset, authResp.bssAddr, authResp.len_bssAddr);
    copyOffset = copyOffset + authResp.len_bssAddr;

    memcpy(authRespPacket + copyOffset, authResp.seqNr, authResp.len_seqNr);
    copyOffset = copyOffset + authResp.len_seqNr;

    memcpy(authRespPacket + copyOffset, authResp.authAlg, authResp.len_authAlg);
    copyOffset = copyOffset + authResp.len_authAlg;

    memcpy(authRespPacket + copyOffset, authResp.authSeq, authResp.len_authSeq);
    copyOffset = copyOffset + authResp.len_authSeq;

    memcpy(authRespPacket + copyOffset, authResp.status, authResp.len_status);
    copyOffset = copyOffset + authResp.len_status;

    memcpy(authRespPacket + copyOffset, authResp.fsc, authResp.len_fsc);
    copyOffset = copyOffset + authResp.len_fsc;


    //send packet
    return sendPacket(pcap_h, authRespPacket, packetSize);
}

int sendAssResponse(pcap_t *pcap_h, u_char *dstAddress)
{
    #define numberOfAssInfoElems (1)   //number of information elements

    //definition of all info elements

    infoElem suppRates = {
        1,         //id
        8,         //len
        8,         //real lenght of data
        "\x82\x84\x8b\x96\x0c\x12\x18\x24" //data
    };


    //create array of information elements
    infoElem taggedParams[numberOfAssInfoElems] = {suppRates};

    //length of all info elements, including id and len field
    int len_taggedParams = 0;
    for(int i = 0; i < numberOfAssInfoElems; i++)
    {
        //+2 to include id and len field size
        len_taggedParams = len_taggedParams + taggedParams[i].len_data+2; 
    }

    //fill in struct
    assResponse assResp = { 
        36, radioTapHeader,                //RadioTap hdr   (overwritten by firmware)
        1, "\x10",                         //Type
        1, "\x00",                         //Flags
        2, "\x40\x01",                     //Duration
        6, dstAddress,                     //DST addr
        6, myMAC,                          //Source addr
        6, myMAC,                          //BSS addr
        2, "\x00\x00",                     //Seq nr         (overwritten by firmware)
        2, "\x01\x00",                     //Capab info
        2, "\x00\x00",                     //Status code
        2, "\x01\xc0",                     //Association id
        
        len_taggedParams,
        taggedParams,                      //Information elements

        4, "\x00\x00\x00\x00"              //FSC            (overwritten by firmware)
    };

    //calculate size of final packet
    int packetSize = assResp.len_radioTapHdr 
                + assResp.len_type
                + assResp.len_flags
                + assResp.len_duration
                + assResp.len_destAddr
                + assResp.len_sourceAddr
                + assResp.len_bssAddr
                + assResp.len_seqNr
                + assResp.len_capabInfo
                + assResp.len_status
                + assResp.len_assId
                + assResp.len_taggedParams
                + assResp.len_fsc;

    //define packet
    u_char assRespPacket[packetSize];

    //copy all struct fields into packet
    int copyOffset = 0;

    memcpy(assRespPacket + copyOffset, assResp.radioTapHdr, assResp.len_radioTapHdr);
    copyOffset = copyOffset + assResp.len_radioTapHdr;

    memcpy(assRespPacket + copyOffset, assResp.type, assResp.len_type);
    copyOffset = copyOffset + assResp.len_type;

    memcpy(assRespPacket + copyOffset, assResp.flags, assResp.len_flags);
    copyOffset = copyOffset + assResp.len_flags;

    memcpy(assRespPacket + copyOffset, assResp.duration, assResp.len_duration);
    copyOffset = copyOffset + assResp.len_duration;

    memcpy(assRespPacket + copyOffset, assResp.destAddr, assResp.len_destAddr);
    copyOffset = copyOffset + assResp.len_destAddr;

    memcpy(assRespPacket + copyOffset, assResp.sourceAddr, assResp.len_sourceAddr);
    copyOffset = copyOffset + assResp.len_sourceAddr;

    memcpy(assRespPacket + copyOffset, assResp.bssAddr, assResp.len_bssAddr);
    copyOffset = copyOffset + assResp.len_bssAddr;

    memcpy(assRespPacket + copyOffset, assResp.seqNr, assResp.len_seqNr);
    copyOffset = copyOffset + assResp.len_seqNr;

    memcpy(assRespPacket + copyOffset, assResp.capabInfo, assResp.len_capabInfo);
    copyOffset = copyOffset + assResp.len_capabInfo;

    memcpy(assRespPacket + copyOffset, assResp.status, assResp.len_status);
    copyOffset = copyOffset + assResp.len_status;

    memcpy(assRespPacket + copyOffset, assResp.assId, assResp.len_assId);
    copyOffset = copyOffset + assResp.len_assId;

    //copy all information elements
    for(int i = 0; i < numberOfAssInfoElems; i++)
    {
        memcpy(assRespPacket + copyOffset, &taggedParams[i].id, 1);
        copyOffset = copyOffset + 1;

        memcpy(assRespPacket + copyOffset, &taggedParams[i].len, 1);
        copyOffset = copyOffset + 1;

        memcpy(assRespPacket + copyOffset, taggedParams[i].data, taggedParams[i].len_data);
        copyOffset = copyOffset + taggedParams[i].len_data;
    }
        

    memcpy(assRespPacket + copyOffset, assResp.fsc, assResp.len_fsc);
    copyOffset = copyOffset + assResp.len_fsc;

    //send packet
    return sendPacket(pcap_h, assRespPacket, packetSize);    
}

int sendProbeResponse(pcap_t *pcap_h, u_char *dstAddress)
{
    #define numberOfProbeInfoElems (1)   //number of information elements

    //definition of all info elements

    /*infoElem ssid = {
        0,         //id
        8,         //len
        8,         //real length of data
        "\x43\x43\x43\x43\x43\x43\x43\x43" //data
    };*/
    infoElem ssid = ssidFuzz();

    infoElem suppRates = {
        1,         //id
        7,         //len
        7,         //real length of data
        "\x96\x18\x24\x30\x48\x60\x6c" //data
    };

    infoElem dsParam = {
        3,         //id
        1,         //len
        1,         //real length of data
        "\x01" //data
    };

    //create array of information elements
    infoElem taggedParams[numberOfProbeInfoElems] = {ssid};

    //length of all info elements, including id and len field
    int len_taggedParams = 0;
    for(int i = 0; i < numberOfProbeInfoElems; i++)
    {
        //+2 to include id and len field size
        len_taggedParams = len_taggedParams + taggedParams[i].len_data+2; 
    }

    //fill in struct
    probeResponse probeResp = { 
        36, radioTapHeader,                //RadioTap hdr   (overwritten by firmware)
        1, "\x50",                         //Type
        1, "\x00",                         //Flags
        2, "\x3a\x01",                     //Duration
        6, dstAddress,                     //DST addr
        6, myMAC,                          //Source addr
        6, myMAC,                          //BSS addr
        2, "\x00\x00",                     //Seq nr         (overwritten by firmware)
        8, "\x00\x00\x00\x00\x00\x00\x00\x00", //Timestamp  (overwritten by firmware)
        2, "\x64\x00",                     //Beacon interval
        2, "\x01\x00",                     //Capab info
        
        len_taggedParams,
        taggedParams,                      //Information elements

        4, "\x00\x00\x00\x00"              //FSC            (overwritten by firmware)
    };


    //calculate size of final packet
    int packetSize = probeResp.len_radioTapHdr 
                + probeResp.len_type
                + probeResp.len_flags
                + probeResp.len_duration
                + probeResp.len_destAddr
                + probeResp.len_sourceAddr
                + probeResp.len_bssAddr
                + probeResp.len_seqNr
                + probeResp.len_timeStamp
                + probeResp.len_beaconInterval
                + probeResp.len_capabInfo
                + probeResp.len_taggedParams
                + probeResp.len_fsc;

    
    //define packet
    u_char probeRespPacket[packetSize];

    //copy all struct fields into packet
    int copyOffset = 0;

    memcpy(probeRespPacket + copyOffset, probeResp.radioTapHdr, probeResp.len_radioTapHdr);
    copyOffset = copyOffset + probeResp.len_radioTapHdr;

    memcpy(probeRespPacket + copyOffset, probeResp.type, probeResp.len_type);
    copyOffset = copyOffset + probeResp.len_type;

    memcpy(probeRespPacket + copyOffset, probeResp.flags, probeResp.len_flags);
    copyOffset = copyOffset + probeResp.len_flags;

    memcpy(probeRespPacket + copyOffset, probeResp.duration, probeResp.len_duration);
    copyOffset = copyOffset + probeResp.len_duration;

    memcpy(probeRespPacket + copyOffset, probeResp.destAddr, probeResp.len_destAddr);
    copyOffset = copyOffset + probeResp.len_destAddr;

    memcpy(probeRespPacket + copyOffset, probeResp.sourceAddr, probeResp.len_sourceAddr);
    copyOffset = copyOffset + probeResp.len_sourceAddr;

    memcpy(probeRespPacket + copyOffset, probeResp.bssAddr, probeResp.len_bssAddr);
    copyOffset = copyOffset + probeResp.len_bssAddr;

    memcpy(probeRespPacket + copyOffset, probeResp.seqNr, probeResp.len_seqNr);
    copyOffset = copyOffset + probeResp.len_seqNr;

    memcpy(probeRespPacket + copyOffset, probeResp.timeStamp, probeResp.len_timeStamp);
    copyOffset = copyOffset + probeResp.len_timeStamp;

    memcpy(probeRespPacket + copyOffset, probeResp.beaconInterval, probeResp.len_beaconInterval);
    copyOffset = copyOffset + probeResp.len_beaconInterval;

    memcpy(probeRespPacket + copyOffset, probeResp.capabInfo, probeResp.len_capabInfo);
    copyOffset = copyOffset + probeResp.len_capabInfo;

    //copy all information elements
    for(int i = 0; i < numberOfProbeInfoElems; i++)
    {
        memcpy(probeRespPacket + copyOffset, &taggedParams[i].id, 1);
        copyOffset = copyOffset + 1;

        memcpy(probeRespPacket + copyOffset, &taggedParams[i].len, 1);
        copyOffset = copyOffset + 1;

        memcpy(probeRespPacket + copyOffset, taggedParams[i].data, taggedParams[i].len_data);
        copyOffset = copyOffset + taggedParams[i].len_data;
    }
        

    memcpy(probeRespPacket + copyOffset, probeResp.fsc, probeResp.len_fsc);
    copyOffset = copyOffset + probeResp.len_fsc;


    //send packet
    return sendPacket(pcap_h, probeRespPacket, packetSize);    
}


int main(int argc, char *argv[])
{
    pcap_t  *pcap_h;
    struct  bpf_program fp;
    struct  pcap_pkthdr header;
    char    *dev;
    char    errbuf[PCAP_ERRBUF_SIZE];

    //initialize libpcap

    if(argc != 2)
    {
        printf("Usage: %s device\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    dev = argv[1];

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

    int waitForACK = 0;

    int noACKcounter = 0;

    //infinite listen-respond loop
    while (1)
    {
        //receive packet
        startTimer();
        const u_char *packet = pcap_next(pcap_h, &header);

        unsigned long long timeSincePrevPacket = stopTimer();

        u_char frameType = getFrameTypeOfPacket(packet);

        u_char* sourceAddr = "\x00\x00\x00\x00\x00\x00";


        if (frameType != 0xd4)
            sourceAddr = getSourceAddrOfPacket(packet);
        


        if (waitForACK != 0)
        {
            if (frameType == 0xd4)
            {
                ackedFrames = ackedFrames + 1;  //the frame is acked, so increase counter
                noACKcounter = 0;
                increaseFuzzer();               //fuzz next thing
                printf("Frame ACKed, fuzzStep is now %lu\n", fuzzStep);
                if (DEBUG)
                {
                    switch (waitForACK)
                    {
                        case 1:
                        {
                            printf("Association Response ACKed\n");
                            break;
                        }
                        case 2:
                        {
                            printf("Authentication frame ACKed\n");
                            break;
                        }
                        case 3:
                        {
                            printf("Probe Response ACKed\n");
                            break;
                        }
                        default:
                        {
                            printf("Frame ACKed\n");
                            break;
                        }
                    }
                }
                
            }
            else
            {
                noACKcounter = noACKcounter + 1;
                if (noACKcounter == 10)
                {
                    printf("Frame not ACKed after 10 retries. State is %lu, step is %lu\n", fuzzState, fuzzStep);
                    noACKcounter = 0;
                    increaseFuzzer();
                }
                if (DEBUG)
                {
                    printf("Not sure if frame was ACKed\n");
                }
            }
            waitForACK = 0;
        }
        else
        {
            switch(frameType)
            {
                case 0x40:
                {
                    sendProbeResponse(pcap_h, sourceAddr);
                    waitForACK = 3;
                    break;
                } 
                case 0xb0:
                {
                    //sendAuthResponse(pcap_h, sourceAddr);
                    //waitForACK = 2;
                    break;
                }
                case 0x00:
                {
                    //sendAssResponse(pcap_h, sourceAddr);
                    //waitForACK = 1;
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
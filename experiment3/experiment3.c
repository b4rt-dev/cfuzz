#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h> 
#include "experiment3.h"

//Copied from wireshark. Will be overwritten by firmware
u_char radioTapHeader[36]   =   "\x00\x00\x24\x00\x2f\x40\x00\xa0\x20\x08\x00\x00\x00\x00\x00\x00" \
                                "\x9d\x5c\xa0\x15\x01\x00\x00\x00\x10\x02\x6c\x09\xa0\x00\xa7\x00" \
                                "\x00\x00\xa7\x00";

//Mac address of Atheros Wi-Fi dongle
u_char myMAC[6]            =  "\x00\x0a\xeb\x2d\x72\x55";

//Returns filter for libpcap
//we want to use as many filters here as possible, since libpcap is closer to the hardware than this user-level program
//we only want to receive Probe requests to only our own MAC address or broadcast address, and ACK frames to our MAC address
const char *getFilterString()
{
    //xx:xx:xx:xx:xx:xx will become myMAC
    static char filterString[] = "(wlan subtype probe-req and (wlan addr1 xx:xx:xx:xx:xx:xx or wlan addr1 ff:ff:ff:ff:ff:ff)) or ( wlan addr1 xx:xx:xx:xx:xx:xx and wlan subtype ack)";

    //convert myMAC to string
    char myMacStr[18];

    snprintf(myMacStr, sizeof(myMacStr), "%02x:%02x:%02x:%02x:%02x:%02x",
             myMAC[0], myMAC[1], myMAC[2], myMAC[3], myMAC[4], myMAC[5]);

    //replace placeholder MACs in filterString with correct MACstring
    strncpy(filterString+40, myMacStr,17);
    strncpy(filterString+108, myMacStr,17);

    return filterString;
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

int sendProbeResponse(pcap_t *pcap_h, u_char *dstAddress)
{
    #define numberOfProbeInfoElems (3)   //number of information elements

    //definition of all information elements
    infoElem ssid = {
        0,         //id
        6,         //len
        6,         //real length of data
        "\x46\x75\x7a\x7a\x41\x50" //data
    };

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
    infoElem taggedParams[numberOfProbeInfoElems] = {ssid, suppRates, dsParam};

    //length of all info elements, including id and len field
    int len_taggedParams = 0;
    for(int i = 0; i < numberOfProbeInfoElems; i++)
    {
        //+2 to include id and len field size
        len_taggedParams = len_taggedParams + taggedParams[i].len_data+2; 
    }

    //fill in frame struct
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

    //infinite listen-respond loop
    while (1)
    {
        //receive packet
        const u_char *packet = pcap_next(pcap_h, &header);

        u_char frameType = getFrameTypeOfPacket(packet);

        u_char* sourceAddr;

        if (frameType != 0xd4) //ACK frames have no source address
            sourceAddr = getSourceAddrOfPacket(packet);

        //if we had to wait for an ACK, verify if current frame is an ACK
        if (waitForACK != 0)
        {
            if (frameType == 0xd4)
            {
                printf("Probe response ACKed\n");
            }
            else
            {
                printf("Not sure if Probe Response was ACKed\n");
            }
            waitForACK = 0;
        }
        else //Process frame depending on type
        {
            switch(frameType)
            {
                case 0x40:
                {
                    sendProbeResponse(pcap_h, sourceAddr);
                    waitForACK = 1;
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

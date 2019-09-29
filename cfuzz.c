/*
NOTES:
- Frames are being ACKed by the firmware as long as the MAC address is correct
- Frames are being retransmitted by the firmware when there is no ACK response (except beacon frames IIRC)

*/

#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h> 
#include "cfuzz.h"

//Copied from wireshark. Will be overwritten by firmware
u_char radioTapHeader[36]   =   "\x00\x00\x24\x00\x2f\x40\x00\xa0\x20\x08\x00\x00\x00\x00\x00\x00" \
                                "\x9d\x5c\xa0\x15\x01\x00\x00\x00\x10\x02\x6c\x09\xa0\x00\xa7\x00" \
                                "\x00\x00\xa7\x00";

//Mac address of Atheros Wi-Fi dongle
//Dongle will only ACK frames to its own MAC address
u_char myMAC[6]            =  "\x00\x0a\xeb\x2d\x72\x55";

//Receives packet with filter and returns packet
const u_char *recvPacket(pcap_t *pcap_h, struct  bpf_program fp, struct  pcap_pkthdr header)
{
    //compile filter for incoming packets
    //we only want to receive Probe requests, Authentication frames and Association requests
    if(pcap_compile(pcap_h, &fp, "wlan subtype probe-req or wlan subtype auth or wlan subtype assoc-req", 0, PCAP_NETMASK_UNKNOWN) == -1)
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

    //wait, receive and return next packet
    return pcap_next(pcap_h, &header);
}

//Places source address from packet in addrArray
void getSourceAddrOfPacket(const u_char *packet, u_char *addrArray)
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

    //copy addr (6 bytes) to addrArray
    memcpy(addrArray, addr, 6);
}

//Places Version, Type and Subtype (two bytes) from packet in typeArray
void getFrameTypeOfPacket(const u_char *packet, u_char *typeArray)
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

    //copy frameType (2 bytes) to typeArray
    memcpy(typeArray, frameType, 2);
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
    u_char response[] = 
    "\x00\x00\x24\x00\x2f\x40\x00\xa0\x20\x08\x00\x00\x00\x00\x00\x00" \
    "\x9d\x5c\xa0\x15\x01\x00\x00\x00\x10\x02\x6c\x09\xa0\x00\xa7\x00" \
    "\x00\x00\xa7\x00" \
    "\x10\x00\x40\x01\xcc\xfa\x00\xc9\xfc\xad\x00\x0a\xeb\x2d\x72\x55\x00\x0a\xeb\x2d\x72\x55\xd0\x39" \
    "\x01\x04\x00\x00\x01\xc0\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24" \
    "\x32\x04\x30\x48\x60\x6c\x2d\x1a\x6c\x08\x1f\xff\x00\x00\x00\x01" \
    "\x00\x00\x00\x00\x00\x96\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x3d\x16\x01\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7f\x08\x00\x00\x00\x00" \
    "\x00\x00\x00\x40\xdd\x18\x00\x50\xf2\x02\x01\x01\x00\x00\x03\xa4" \
    "\x00\x00\x27\xa4\x00\x00\x42\x43\x5d\x00\x62\x32\x2e\x00\x00\x00\x00\x00";

    response[40] = dstAddress[0];
    response[41] = dstAddress[1];
    response[42] = dstAddress[2];
    response[43] = dstAddress[3];
    response[44] = dstAddress[4];
    response[45] = dstAddress[5];

    int sendStatus = pcap_sendpacket(pcap_h, response, sizeof(response)-1);

    return sendStatus;
}

int sendProbeResponse(pcap_t *pcap_h, u_char *dstAddress)
{
    #define numberOfInfoElems (3)   //number of information elements

    //definition of all info elements

    infoElem ssid = {
        0,         //id
        8,         //len
        "\x43\x43\x43\x43\x43\x43\x43\x43" //data
    };

    infoElem suppRates = {
        1,         //id
        7,         //len
        "\x96\x18\x24\x30\x48\x60\x6c" //data
    };

    infoElem dsParam = {
        3,         //id
        1,         //len
        "\x01" //data
    };

    //create array of information elements
    infoElem taggedParams[numberOfInfoElems] = {ssid, suppRates, dsParam};

    //length of all info elements, including id and len field
    int len_taggedParams = 0;
    for(int i = 0; i < numberOfInfoElems; i++)
    {
        //+2 to include id and len field size
        len_taggedParams = len_taggedParams + taggedParams[i].len+2; 
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
    for(int i = 0; i < numberOfInfoElems; i++)
    {
        memcpy(probeRespPacket + copyOffset, &taggedParams[i].id, 1);
        copyOffset = copyOffset + 1;

        memcpy(probeRespPacket + copyOffset, &taggedParams[i].len, 1);
        copyOffset = copyOffset + 1;

        memcpy(probeRespPacket + copyOffset, taggedParams[i].data, taggedParams[i].len);
        copyOffset = copyOffset + taggedParams[i].len;
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


    //infinite listen-respond loop
    while (1)
    {
        //receive packet
        const u_char *packet = recvPacket(pcap_h, fp, header);

        u_char sourceAddr[6];
        getSourceAddrOfPacket(packet, sourceAddr);

        u_char frameType[2];
        getFrameTypeOfPacket(packet, frameType);

        //ignore own sent frames
        if (memcmp(sourceAddr, myMAC, 6) != 0)
        {
            //probe request
            if (frameType[0] == 0x40 && frameType[1] == 0x00)
            {
                sendProbeResponse(pcap_h, sourceAddr);
            }

            //authentication
            if (frameType[0] == 0xb0 && frameType[1] == 0x00)
            {        
                 sendAuthResponse(pcap_h, sourceAddr);
            }

            //association request
            if (frameType[0] == 0x00 && frameType[1] == 0x00)
            { 
                 sendAssResponse(pcap_h, sourceAddr);
            }
        }
    }

    return 0;
}
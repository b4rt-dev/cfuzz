/*
Creates frames.
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "frameCreator.h"
#include "fuzzer.h"
#include "frameDefinitions.h"
#include "fuzzSSID.h"

//Creates Probe response frame
u_char *createProbeResponse(u_char *dstAddress, int *packetSize, u_char * radioTapHeader, u_char *myMAC)
{
    #define numberOfProbeInfoElems (3)   //number of information elements

    //definition of all info elements 
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
    infoElem taggedParams[numberOfProbeInfoElems] = {ssid, suppRates, dsParam};

    //length of all info elements, including id and len field
    int len_taggedParams = 0;
    for(int i = 0; i < numberOfProbeInfoElems; i++)
    {
        if (taggedParams[i].len_data != -1) //do not include when len_data == -1
        {
            //+2 to include id and len field size
            len_taggedParams = len_taggedParams + taggedParams[i].len_data+2; 
        }
    }

    //fill in struct
    probeResponse probeResp = { 
        36, radioTapHeader,                //RadioTap hdr
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
    *packetSize = probeResp.len_radioTapHdr 
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
    u_char *probeRespPacket = malloc(*packetSize);
    if(!probeRespPacket)
    {
        printf("Memory allocation error!\n");
        exit(-1);
    }

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
        if (taggedParams[i].len_data != -1)  //if id == -1, we do not want to include the information element
        {
            memcpy(probeRespPacket + copyOffset, &taggedParams[i].id, 1);
            copyOffset = copyOffset + 1;

            memcpy(probeRespPacket + copyOffset, &taggedParams[i].len, 1);
            copyOffset = copyOffset + 1;

            memcpy(probeRespPacket + copyOffset, taggedParams[i].data, taggedParams[i].len_data);
            copyOffset = copyOffset + taggedParams[i].len_data;
        }
    }
        

    memcpy(probeRespPacket + copyOffset, probeResp.fsc, probeResp.len_fsc);
    copyOffset = copyOffset + probeResp.len_fsc;

    //return packet
    return probeRespPacket;    
}
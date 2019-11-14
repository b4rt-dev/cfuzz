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
#include "fuzzRates.h"
#include "fuzzFH.h"
//CHANGE WHEN NEW SUBFUZZER


//Creates Authentication frame
u_char *createAuthResponse(u_char *dstAddress, int *packetSize, u_char * radioTapHeader, u_char *myMAC)
{
    //fill in struct
    authResponse authResp = { 
        36, radioTapHeader,                //RadioTap hdr
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
    *packetSize = authResp.len_radioTapHdr 
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
    u_char *authRespPacket = malloc(*packetSize);
    if(!authRespPacket)
    {
        printf("Memory allocation error!\n");
        exit(-1);
    }

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
    return authRespPacket;
}

//Creates Association response
u_char *createAssResponse(u_char *dstAddress, int *packetSize, u_char * radioTapHeader, u_char *myMAC)
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
        if (taggedParams[i].len_data != -1) //do not include if len_data == -1
        {
            //+2 to include id and len field size
            len_taggedParams = len_taggedParams + taggedParams[i].len_data+2; 
        }
    }

    //fill in struct
    assResponse assResp = { 
        36, radioTapHeader,                //RadioTap hdr
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
    *packetSize = assResp.len_radioTapHdr 
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
    u_char *assRespPacket = malloc(*packetSize);
    if(!assRespPacket)
    {
        printf("Memory allocation error!\n");
        exit(-1);
    }

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
        if (taggedParams[i].len_data != -1)  //if id == -1, we do not want to include the information element
        {
            memcpy(assRespPacket + copyOffset, &taggedParams[i].id, 1);
            copyOffset = copyOffset + 1;

            memcpy(assRespPacket + copyOffset, &taggedParams[i].len, 1);
            copyOffset = copyOffset + 1;

            memcpy(assRespPacket + copyOffset, taggedParams[i].data, taggedParams[i].len_data);
            copyOffset = copyOffset + taggedParams[i].len_data;
        }
    }
        

    memcpy(assRespPacket + copyOffset, assResp.fsc, assResp.len_fsc);
    copyOffset = copyOffset + assResp.len_fsc;

    //send packet
    return assRespPacket;    
}

//Creates Probe response frame
u_char *createProbeResponse(u_char *dstAddress, int *packetSize, u_char * radioTapHeader, u_char *myMAC)
{
    //CHANGE WHEN NEW SUBFUZZER
    #define numberOfProbeInfoElems (4)   //number of information elements

    //definition of all info elements

    infoElem ssid = ssidFuzz();

    infoElem suppRates = ratesFuzz();

    infoElem fh = fhFuzz();

    infoElem dsParam = {
        3,         //id
        1,         //len
        1,         //real length of data
        "\x01" //data
    };

    //CHANGE WHEN NEW SUBFUZZER


    //CHANGE WHEN NEW SUBFUZZER
    //create array of information elements
    infoElem taggedParams[numberOfProbeInfoElems] = {ssid, suppRates, fh, dsParam};

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
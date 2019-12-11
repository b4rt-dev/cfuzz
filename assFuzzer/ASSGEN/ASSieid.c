/*
Fuzzes AssResp by testing all 256 IEs on overflow in four ways
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "../frameDefinitions.h"

//Creates Probe response frame
u_char *Assieid(u_char *dstAddress, int *packetSize, u_char * radioTapHeader, u_char *myMAC, int step)
{

    #define AssieidIES  (2)   //number of information elements

    infoElem suppRates = {
        1,         //id
        7,         //len
        7,         //real length of data
        "\x96\x18\x24\x30\x48\x60\x6c" //data
    };


    infoElem fuzzIE;

    switch(step % 4)
    {
        case 0:
        {
            fuzzIE.id = step/4;
            fuzzIE.len = 255;
            fuzzIE.len_data = 255;
            //create data of 255 times 0xff
            u_char *data = malloc(255);
            memset(data, 0xff, 255);
            fuzzIE.data = data;
            break;
        }
        case 1:
        {
            fuzzIE.id = step/4;
            fuzzIE.len = 0;
            fuzzIE.len_data = 0;
            fuzzIE.data = "";
            break;
        }
        case 2:
        {
            fuzzIE.id = step/4;
            fuzzIE.len = 253;
            fuzzIE.len_data = 253;
            //create data of 253 times 0xff
            u_char *data = malloc(253);
            memset(data, 0xff, 253);
            fuzzIE.data = data;
            break;
        }
        case 3:
        {
            fuzzIE.id = step/4;
            fuzzIE.len = 255;
            fuzzIE.len_data = 255;
            //create data of 255 times 0x00
            u_char *data = malloc(255);
            memset(data, 0x00, 255);
            fuzzIE.data = data;
            break;
        }
    }


    //create array of information elements
    infoElem taggedParams[AssieidIES] = {suppRates, fuzzIE};

    //length of all info elements, including id and len field
    int len_taggedParams = 0;
    for(int i = 0; i < AssieidIES; i++)
    {
        if (taggedParams[i].len_data != -1) //do not include when len_data == -1
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
    for(int i = 0; i < AssieidIES; i++)
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
/*
Fuzzes AuthResp by testing all 256 IEs on overflow in four ways
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "../frameDefinitions.h"

//Creates Probe response frame
u_char *Authieid(u_char *dstAddress, int *packetSize, u_char * radioTapHeader, u_char *myMAC, int step)
{

    #define AuthieidIES  (2)   //number of information elements

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
    infoElem taggedParams[AuthieidIES] = {suppRates, fuzzIE};

    //length of all info elements, including id and len field
    int len_taggedParams = 0;
    for(int i = 0; i < AuthieidIES; i++)
    {
        if (taggedParams[i].len_data != -1) //do not include when len_data == -1
        {
            //+2 to include id and len field size
            len_taggedParams = len_taggedParams + taggedParams[i].len_data+2; 
        }
    }

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

        len_taggedParams,
        taggedParams,                      //Information elements

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
                + authResp.len_taggedParams
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

    //copy all information elements
    for(int i = 0; i < AuthieidIES; i++)
    {
        if (taggedParams[i].len_data != -1)  //if id == -1, we do not want to include the information element
        {
            memcpy(authRespPacket + copyOffset, &taggedParams[i].id, 1);
            copyOffset = copyOffset + 1;

            memcpy(authRespPacket + copyOffset, &taggedParams[i].len, 1);
            copyOffset = copyOffset + 1;

            memcpy(authRespPacket + copyOffset, taggedParams[i].data, taggedParams[i].len_data);
            copyOffset = copyOffset + taggedParams[i].len_data;
        }
    }
        

    memcpy(authRespPacket + copyOffset, authResp.fsc, authResp.len_fsc);
    copyOffset = copyOffset + authResp.len_fsc;

    //send packet
    return authRespPacket;    

}
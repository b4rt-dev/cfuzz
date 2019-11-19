/*
Fuzzes vendor specific Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the vendorFuzzer is running
int vendorRunningState = 0;

//Number of fuzzing states
const int vendorStates =  17;
//Steps of fuzzers for each fuzzing state
const int vendorSteps[] =   {1, 8, 2, 2, 2, 2,2,2,2,2,2,2,2,2,2,2,2};

//Current state and step of the vendorFuzzer
int fuzzState;
int fuzzStep;

void vendorPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing vendor IE\e[39m\n");
            printf("Trying 255*0xFF data\n");
            break;
        }
        case 1: 
        {
            printf("fuzzing low lengths\n");
            break;
        }
        case 2: 
        {
            printf("fuzzing WMM/WME\n");
            break;
        }
        case 3: 
        {
            printf("fuzzing WPA\n");
            break;
        }
        case 4: 
        {
            printf("fuzzing WPS\n");
            break;
        }
        case 5: 
        {
            printf("fuzzing WPS Version length\n");
            break;
        }
        case 6: 
        {
            printf("fuzzing WPS wpss length\n");
            break;
        }
        case 7: 
        {
            printf("fuzzing WPS model number length\n");
            break;
        }
        case 8: 
        {
            printf("fuzzing WPS response type length\n");
            break;
        }
        case 9: 
        {
            printf("fuzzing WPS uuid length\n");
            break;
        }
        case 10: 
        {
            printf("fuzzing WPS manufacturer length\n");
            break;
        }
        case 11: 
        {
            printf("fuzzing WPS model name length\n");
            break;
        }
        case 12: 
        {
            printf("fuzzing WPS primary device type length\n");
            break;
        }
        case 13: 
        {
            printf("fuzzing WPS device name length\n");
            break;
        }
        case 14: 
        {
            printf("fuzzing WPS config methods length\n");
            break;
        }
        case 15: 
        {
            printf("fuzzing WPS rf bands length\n");
            break;
        }
        case 16: 
        {
            printf("fuzzing WPS vendor extension length\n");
            break;
        }
        case 17:
        {
            printf("\e[33mDone with fuzzing vendor\e[39m\n");
            break;
        }
    }
}

//Updates vendorFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int vendorFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            vendorRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            vendorPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (vendorRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < vendorSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    vendorPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == vendorStates)
                {
                    vendorRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            vendorRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an vendor information element
infoElem vendorFuzz()
{
    infoElem vendor;

    //What to return when not fuzzed
    if (vendorRunningState == 0)
    {
        vendor.id = 0;
        vendor.len = 1;
        vendor.len_data = -1;
        vendor.data = "\xab";
    }
    else
    {
        switch (fuzzState) //update this
        {
            case 0:     //255*0xff
            {
                vendor.id = 221;
                vendor.len = 255;
                vendor.len_data = 255;
                //create data of 255 times 0xff
                u_char *data = malloc(255);
                memset(data, 0xff, 255);
                vendor.data = data;
                break;
            }
            case 1:  //short lengths
            {
                int dataSize = 0 + fuzzStep;

                vendor.id = 221; 
                vendor.len = dataSize;
                vendor.len_data = dataSize;
                //create data of datasize times 0xFF
                u_char *data = malloc(dataSize);
                memset(data, 0xFF, dataSize);
                vendor.data = data;
                break;
            } 
            case 2:
            {
                if (fuzzStep == 0)
                {
                    vendor.id = 221;
                    vendor.len = 255;
                    vendor.len_data = 255;
                    u_char *data = malloc(255);
                    memset(data, 0xFF, 255);
                    data[0] = 0x00; //oui
                    data[1] = 0x50; //oui
                    data[2] = 0xf2; //oui
                    data[3] = 0x02; //type

                    vendor.data = data;
                }
                if (fuzzStep == 1)
                {
                    vendor.id = 221;
                    vendor.len = 4;
                    vendor.len_data = 4;
                    vendor.data = "\x00\x50\xf2\x02";
                }
                break;
            } 
            case 3:
            {
                if (fuzzStep == 0)
                {
                    vendor.id = 221;
                    vendor.len = 255;
                    vendor.len_data = 255;
                    u_char *data = malloc(255);
                    memset(data, 0xFF, 255);
                    data[0] = 0x00; //oui
                    data[1] = 0x50; //oui
                    data[2] = 0xf2; //oui
                    data[3] = 0x01; //type

                    vendor.data = data;
                }
                if (fuzzStep == 1)
                {
                    vendor.id = 221;
                    vendor.len = 4;
                    vendor.len_data = 4;
                    vendor.data = "\x00\x50\xf2\x01";
                }
                break;
            } 
            case 4:
            {
                if (fuzzStep == 0)
                {
                    vendor.id = 221;
                    vendor.len = 255;
                    vendor.len_data = 255;
                    u_char *data = malloc(255);
                    memset(data, 0xFF, 255);
                    data[0] = 0x00; //oui
                    data[1] = 0x50; //oui
                    data[2] = 0xf2; //oui
                    data[3] = 0x04; //type

                    vendor.data = data;
                }
                if (fuzzStep == 1)
                {
                    vendor.id = 221;
                    vendor.len = 4;
                    vendor.len_data = 4;
                    vendor.data = "\x00\x50\xf2\x04";
                }
                break;
            } 
            default:
            {
                if (fuzzStep == 0)
                {
                    vendor.id = 221;
                    vendor.len = 255;
                    vendor.len_data = 255;
                    u_char *data = malloc(255);
                    memset(data, 0xFF, 255);
                    data[0] = 0x00; //oui
                    data[1] = 0x50; //oui
                    data[2] = 0xf2; //oui
                    data[3] = 0x04; //type
                    switch (fuzzState)
                    {
                        case 5:{
                            data[4] = 0x10; //id
                            data[5] = 0x4a; //id
                            break;
                        }
                        case 6:{
                            data[4] = 0x10; //id
                            data[5] = 0x44; //id
                            break;
                        }
                        case 7:{
                            data[4] = 0x10; //id
                            data[5] = 0x24; //id
                            break;
                        }
                        case 8:{
                            data[4] = 0x10; //id
                            data[5] = 0x3b; //id
                            break;
                        }
                        case 9:{
                            data[4] = 0x10; //id
                            data[5] = 0x47; //id
                            break;
                        }
                        case 10:{
                            data[4] = 0x10; //id
                            data[5] = 0x21; //id
                            break;
                        }
                        case 11:{
                            data[4] = 0x10; //id
                            data[5] = 0x23; //id
                            break;
                        }
                        case 12:{
                            data[4] = 0x10; //id
                            data[5] = 0x54; //id
                            break;
                        }
                        case 13:{
                            data[4] = 0x10; //id
                            data[5] = 0x11; //id
                            break;
                        }
                        case 14:{
                            data[4] = 0x10; //id
                            data[5] = 0x08; //id
                            break;
                        }
                        case 15:{
                            data[4] = 0x10; //id
                            data[5] = 0x3c; //id
                            break;
                        }
                        case 16:{
                            data[4] = 0x10; //id
                            data[5] = 0x49; //id
                            break;
                        }
                    }
                        
                    data[6] = 0x00; //len
                    data[7] = 247; //len
                    vendor.data = data;
                }
                if (fuzzStep == 1)
                {
                    vendor.id = 221;
                    vendor.len = 255;
                    vendor.len_data = 255;
                    u_char *data = malloc(255);
                    memset(data, 0xFF, 255);
                    data[0] = 0x00; //oui
                    data[1] = 0x50; //oui
                    data[2] = 0xf2; //oui
                    data[3] = 0x04; //type
                    switch (fuzzState)
                    {
                        case 5:{
                            data[4] = 0x10; //id
                            data[5] = 0x4a; //id
                            break;
                        }
                        case 6:{
                            data[4] = 0x10; //id
                            data[5] = 0x44; //id
                            break;
                        }
                        case 7:{
                            data[4] = 0x10; //id
                            data[5] = 0x24; //id
                            break;
                        }
                        case 8:{
                            data[4] = 0x10; //id
                            data[5] = 0x3b; //id
                            break;
                        }
                        case 9:{
                            data[4] = 0x10; //id
                            data[5] = 0x47; //id
                            break;
                        }
                        case 10:{
                            data[4] = 0x10; //id
                            data[5] = 0x21; //id
                            break;
                        }
                        case 11:{
                            data[4] = 0x10; //id
                            data[5] = 0x23; //id
                            break;
                        }
                        case 12:{
                            data[4] = 0x10; //id
                            data[5] = 0x54; //id
                            break;
                        }
                        case 13:{
                            data[4] = 0x10; //id
                            data[5] = 0x11; //id
                            break;
                        }
                        case 14:{
                            data[4] = 0x10; //id
                            data[5] = 0x08; //id
                            break;
                        }
                        case 15:{
                            data[4] = 0x10; //id
                            data[5] = 0x3c; //id
                            break;
                        }
                        case 16:{
                            data[4] = 0x10; //id
                            data[5] = 0x49; //id
                            break;
                        }
                    }
                    data[6] = 0xff; //len
                    data[7] = 0xff; //len
                    vendor.data = data;
                }
                break;
            }
        }
    }
    
    return vendor;
}
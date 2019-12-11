/*
Fuzzes erp Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the erpFuzzer is running
int erpRunningState = 0;

//Number of fuzzing states
const int erpStates =  4;
//Steps of fuzzers for each fuzzing state
const int erpSteps[] =   {1, 2, 16, 16};

//Current state and step of the erpFuzzer
int fuzzState;
int fuzzStep;

void erpPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing erp IE\e[39m\n");
            printf("Trying 255*0xFF data\n");
            break;
        }
        case 1: 
        {
            printf("Fuzzing data\n");
            break;
        }
        case 2: 
        {
            printf("Fuzzing lengths with 0xFF data\n");
            break;
        }
        case 3: 
        {
            printf("Fuzzing lengths with 0x00 data\n");
            break;
        }
        case 4:
        {
            printf("\e[33mDone with fuzzing erp\e[39m\n");
            break;
        }
    }
}

//Updates erpFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int erpFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            erpRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            erpPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (erpRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < erpSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    erpPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == erpStates)
                {
                    erpRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            erpRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an erp information element
infoElem erpFuzz()
{
    infoElem erp;

    //What to return when not fuzzed
    if (erpRunningState == 0)
    {
        erp.id = 0;
        erp.len = 1;
        erp.len_data = -1;
        erp.data = "\xab";
    }
    else
    {
        switch (fuzzState) //update this
        {
            case 0:     //255*0xff
            {
                erp.id = 42;
                erp.len = 255;
                erp.len_data = 255;
                //create data of 255 times 0xff
                u_char *data = malloc(255);
                memset(data, 0xff, 255);
                erp.data = data;
                break;
            }
            case 1:  //erp data
            {
                if (fuzzStep == 0)
                {
                    erp.id = 42;
                    erp.len = 1;
                    erp.len_data = 1;
                    erp.data = "\x00";
                }
                else
                {
                    erp.id = 42;
                    erp.len = 1;
                    erp.len_data = 1;
                    erp.data = "\xFF";
                }
                
                break;
            } 
            case 2:  //length with 0xff data
            {
                if (fuzzStep < 8)
                {
                    int dataSize = fuzzStep;

                    erp.id = 42;
                    erp.len = dataSize;
                    erp.len_data = dataSize;
                    //create data of datasize times 0xff
                    u_char *data = malloc(dataSize);
                    memset(data, 0xff, dataSize);
                    erp.data = data;
                }
                else
                {
                    int dataSize = 255 - fuzzStep + 8;

                    erp.id = 42;
                    erp.len = dataSize;
                    erp.len_data = dataSize;
                    //create data of datasize times 0xff
                    u_char *data = malloc(dataSize);
                    memset(data, 0xff, dataSize);
                    erp.data = data;
                }
                break;
            } 
            case 3:  //length with 0x00 data
            {
                if (fuzzStep < 8)
                {
                    int dataSize = fuzzStep;

                    erp.id = 42;
                    erp.len = dataSize;
                    erp.len_data = dataSize;
                    //create data of datasize times 0x00
                    u_char *data = malloc(dataSize);
                    memset(data, 0x00, dataSize);
                    erp.data = data;
                }
                else
                {
                    int dataSize = 255 - fuzzStep + 8;

                    erp.id = 42;
                    erp.len = dataSize;
                    erp.len_data = dataSize;
                    //create data of datasize times 0x00
                    u_char *data = malloc(dataSize);
                    memset(data, 0x00, dataSize);
                    erp.data = data;
                }
                break;
            } 
        }
    }
    
    return erp;
}
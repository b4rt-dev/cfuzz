/*
Fuzzes bss load Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the bssloadFuzzer is running
int bssloadRunningState = 0;

//Number of fuzzing states
const int bssloadStates =  3;
//Steps of fuzzers for each fuzzing state
const int bssloadSteps[] =   {1, 16, 16};

//Current state and step of the bssloadFuzzer
int fuzzState;
int fuzzStep;

void bssloadPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing bssload IE\e[39m\n");
            printf("Trying 255*0xFF data\n");
            break;
        }
        case 1: 
        {
            printf("Fuzzing lengths with 0xFF data\n");
            break;
        }
        case 2: 
        {
            printf("Fuzzing lengths with 0x00 data\n");
            break;
        }
        case 3:
        {
            printf("\e[33mDone with fuzzing bssload\e[39m\n");
            break;
        }
    }
}

//Updates bssloadFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int bssloadFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            bssloadRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            bssloadPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (bssloadRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < bssloadSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    bssloadPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == bssloadStates)
                {
                    bssloadRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            bssloadRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an bssload information element
infoElem bssloadFuzz()
{
    infoElem bssload;

    //What to return when not fuzzed
    if (bssloadRunningState == 0)
    {
        bssload.id = 0;
        bssload.len = 1;
        bssload.len_data = -1;
        bssload.data = "\xab";
    }
    else
    {
        switch (fuzzState) //update this
        {
            case 0:     //255*0xff
            {
                bssload.id = 11;
                bssload.len = 255;
                bssload.len_data = 255;
                //create data of 255 times 0xff
                u_char *data = malloc(255);
                memset(data, 0xff, 255);
                bssload.data = data;
                break;
            }
            case 1:  //length with 0xff data
            {
                if (fuzzStep < 8)
                {
                    int dataSize = fuzzStep;

                    bssload.id = 11;
                    bssload.len = dataSize;
                    bssload.len_data = dataSize;
                    //create data of datasize times 0xff
                    u_char *data = malloc(dataSize);
                    memset(data, 0xff, dataSize);
                    bssload.data = data;
                }
                else
                {
                    int dataSize = 255 - fuzzStep + 8;

                    bssload.id = 11;
                    bssload.len = dataSize;
                    bssload.len_data = dataSize;
                    //create data of datasize times 0xff
                    u_char *data = malloc(dataSize);
                    memset(data, 0xff, dataSize);
                    bssload.data = data;
                }
                break;
            } 
            case 2:  //length with 0x00 data
            {
                if (fuzzStep < 8)
                {
                    int dataSize = fuzzStep;

                    bssload.id = 11;
                    bssload.len = dataSize;
                    bssload.len_data = dataSize;
                    //create data of datasize times 0x00
                    u_char *data = malloc(dataSize);
                    memset(data, 0x00, dataSize);
                    bssload.data = data;
                }
                else
                {
                    int dataSize = 255 - fuzzStep + 8;

                    bssload.id = 11;
                    bssload.len = dataSize;
                    bssload.len_data = dataSize;
                    //create data of datasize times 0x00
                    u_char *data = malloc(dataSize);
                    memset(data, 0x00, dataSize);
                    bssload.data = data;
                }
                break;
            } 
        }
    }
    
    return bssload;
}
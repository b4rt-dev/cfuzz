/*
Fuzzes ht capabilities Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the htcapabFuzzer is running
int htcapabRunningState = 0;

//Number of fuzzing states
const int htcapabStates =  4;
//Steps of fuzzers for each fuzzing state
const int htcapabSteps[] =   {1, 2, 32, 32};

//Current state and step of the htcapabFuzzer
int fuzzState;
int fuzzStep;

void htcapabPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing htcapab IE\e[39m\n");
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
            printf("\e[33mDone with fuzzing htcapab\e[39m\n");
            break;
        }
    }
}

//Updates htcapabFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int htcapabFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            htcapabRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            htcapabPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (htcapabRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < htcapabSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    htcapabPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == htcapabStates)
                {
                    htcapabRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            htcapabRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an htcapab information element
infoElem htcapabFuzz()
{
    infoElem htcapab;

    //What to return when not fuzzed
    if (htcapabRunningState == 0)
    {
        htcapab.id = 0;
        htcapab.len = 1;
        htcapab.len_data = -1;
        htcapab.data = "\xab";
    }
    else
    {
        switch (fuzzState) //update this
        {
            case 0:     //255*0xff
            {
                htcapab.id = 45;
                htcapab.len = 255;
                htcapab.len_data = 255;
                //create data of 255 times 0xff
                u_char *data = malloc(255);
                memset(data, 0xff, 255);
                htcapab.data = data;
                break;
            }
            case 1:  //htcapab data
            {
                if (fuzzStep == 0)
                {
                    htcapab.id = 45;
                    htcapab.len = 1;
                    htcapab.len_data = 1;
                    htcapab.data = "\x00";
                }
                else
                {
                    htcapab.id = 45;
                    htcapab.len = 1;
                    htcapab.len_data = 1;
                    htcapab.data = "\xFF";
                }
                
                break;
            } 
            case 2:  //length with 0xff data
            {
                if (fuzzStep < 28)
                {
                    int dataSize = fuzzStep;

                    htcapab.id = 45;
                    htcapab.len = dataSize;
                    htcapab.len_data = dataSize;
                    //create data of datasize times 0xff
                    u_char *data = malloc(dataSize);
                    memset(data, 0xff, dataSize);
                    htcapab.data = data;
                }
                else
                {
                    int dataSize = 255 - fuzzStep + 28;

                    htcapab.id = 45;
                    htcapab.len = dataSize;
                    htcapab.len_data = dataSize;
                    //create data of datasize times 0xff
                    u_char *data = malloc(dataSize);
                    memset(data, 0xff, dataSize);
                    htcapab.data = data;
                }
                break;
            } 
            case 3:  //length with 0x00 data
            {
                if (fuzzStep < 28)
                {
                    int dataSize = fuzzStep;

                    htcapab.id = 45;
                    htcapab.len = dataSize;
                    htcapab.len_data = dataSize;
                    //create data of datasize times 0x00
                    u_char *data = malloc(dataSize);
                    memset(data, 0x00, dataSize);
                    htcapab.data = data;
                }
                else
                {
                    int dataSize = 255 - fuzzStep + 28;

                    htcapab.id = 45;
                    htcapab.len = dataSize;
                    htcapab.len_data = dataSize;
                    //create data of datasize times 0x00
                    u_char *data = malloc(dataSize);
                    memset(data, 0x00, dataSize);
                    htcapab.data = data;
                }
                break;
            } 
        }
    }
    
    return htcapab;
}
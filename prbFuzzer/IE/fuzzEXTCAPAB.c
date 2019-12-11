/*
Fuzzes ext capabilities Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the extcapabFuzzer is running
int extcapabRunningState = 0;

//Number of fuzzing states
const int extcapabStates =  3;
//Steps of fuzzers for each fuzzing state
const int extcapabSteps[] =   {1, 8, 8};

//Current state and step of the extcapabFuzzer
int fuzzState;
int fuzzStep;

void extcapabPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing extcapab IE\e[39m\n");
            printf("Trying 255*0xFF data\n");
            break;
        }
        case 1: 
        {
            printf("Fuzzing large lengths with 0xFF data\n");
            break;
        }
        case 2: 
        {
            printf("Fuzzing large lengths with 0x00 data\n");
            break;
        }
        case 3:
        {
            printf("\e[33mDone with fuzzing extcapab\e[39m\n");
            break;
        }
    }
}

//Updates extcapabFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int extcapabFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            extcapabRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            extcapabPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (extcapabRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < extcapabSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    extcapabPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == extcapabStates)
                {
                    extcapabRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            extcapabRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an extcapab information element
infoElem extcapabFuzz()
{
    infoElem extcapab;

    //What to return when not fuzzed
    if (extcapabRunningState == 0)
    {
        extcapab.id = 0;
        extcapab.len = 1;
        extcapab.len_data = -1;
        extcapab.data = "\xab";
    }
    else
    {
        switch (fuzzState) //update this
        {
            case 0:     //255*0xff
            {
                extcapab.id = 127;
                extcapab.len = 255;
                extcapab.len_data = 255;
                //create data of 255 times 0xff
                u_char *data = malloc(255);
                memset(data, 0xff, 255);
                extcapab.data = data;
                break;
            }
            case 1:  //length with 0xff data
            {
                int dataSize = 255 - fuzzStep;

                extcapab.id = 127;
                extcapab.len = dataSize;
                extcapab.len_data = dataSize;
                //create data of datasize times 0xff
                u_char *data = malloc(dataSize);
                memset(data, 0xff, dataSize);
                extcapab.data = data;
                break;
            } 
            case 2:  //length with 0x00 data
            {
                int dataSize = 255 - fuzzStep;

                extcapab.id = 127;
                extcapab.len = dataSize;
                extcapab.len_data = dataSize;
                //create data of datasize times 0x00
                u_char *data = malloc(dataSize);
                memset(data, 0x00, dataSize);
                extcapab.data = data;
                break;
            } 
        }
    }
    
    return extcapab;
}
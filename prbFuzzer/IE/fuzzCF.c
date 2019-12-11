/*
Fuzzes CF Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the cfFuzzer is running
int cfRunningState = 0;

//Number of fuzzing states
const int cfStates =  3; 
//Steps of fuzzers for each fuzzing state
const int cfSteps[] =   {1, 32, 32};

//Current state and step of the cfFuzzer
int fuzzState;
int fuzzStep;

void cfPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing CF IE\e[39m\n");
            printf("Trying 255*0xFF data\n");
            break;
        }
        case 1: 
        {
            printf("Fuzzing lengths with 0xff data\n");
            break;
        }
        case 2: 
        {
            printf("Fuzzing lengths with 0x00 data\n");
            break;
        }
        case 3:
        {
            printf("\e[33mDone with fuzzing cf\e[39m\n");
            break;
        }
    }
}

//Updates cfFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int cfFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            cfRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            cfPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (cfRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < cfSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    cfPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == cfStates)
                {
                    cfRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            cfRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an cf information element
infoElem cfFuzz()
{
    infoElem cf;

    //What to return when not fuzzed
    if (cfRunningState == 0) 
    {
        cf.id = 4;
        cf.len = 1;
        cf.len_data = -1;
        cf.data = "\xab";
    }
    else
    {
        switch (fuzzState)
        {
            case 0:     //255*0xff
            {
                cf.id = 4; //update this
                cf.len = 255;
                cf.len_data = 255;
                //create data of 255 times 0xff
                u_char *data = malloc(255);
                memset(data, 0xff, 255);
                cf.data = data;
                break;
            }
            case 1:  //cf length with 0xff data
            {
                if (fuzzStep < 16)
                {
                    int dataSize = fuzzStep;

                    cf.id = 4;
                    cf.len = dataSize;
                    cf.len_data = dataSize;
                    //create data of datasize times 0xff
                    u_char *data = malloc(dataSize);
                    memset(data, 0xff, dataSize);
                    cf.data = data;
                }
                else
                {
                    int dataSize = 255 - fuzzStep + 16;

                    cf.id = 4;
                    cf.len = dataSize;
                    cf.len_data = dataSize;
                    //create data of datasize times 0xff
                    u_char *data = malloc(dataSize);
                    memset(data, 0xff, dataSize);
                    cf.data = data;
                }
                break;
            } 
            case 2:  //cf length with 0x00 data
            {
                if (fuzzStep < 16)
                {
                    int dataSize = fuzzStep;

                    cf.id = 4;
                    cf.len = dataSize;
                    cf.len_data = dataSize;
                    //create data of datasize times 0x00
                    u_char *data = malloc(dataSize);
                    memset(data, 0x00, dataSize);
                    cf.data = data;
                }
                else
                {
                    int dataSize = 255 - fuzzStep + 16;

                    cf.id = 4;
                    cf.len = dataSize;
                    cf.len_data = dataSize;
                    //create data of datasize times 0x00
                    u_char *data = malloc(dataSize);
                    memset(data, 0x00, dataSize);
                    cf.data = data;
                }
                break;
            } 
        }
    }
    
    return cf;
}
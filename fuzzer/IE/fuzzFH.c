/*
Fuzzes FH Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the fhFuzzer is running
int fhRunningState = 0;

//Number of fuzzing states
const int fhStates =  2;
//Steps of fuzzers for each fuzzing state
const int fhSteps[] =   {1, 32}; 

//Current state and step of the fhFuzzer
int fuzzState;
int fuzzStep;

void fhPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing FH IE\e[39m\n");
            printf("Trying 255*0xFF data\n");
            break;
        }
        case 1: 
        {
            printf("Fuzzing different lengths\n");
            break;
        }
        case 2:
        {
            printf("\e[33mDone with fuzzing FH IE\e[39m\n");
            break;
        }
    }
}

//Updates fhFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int fhFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            fhRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            fhPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (fhRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < fhSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    fhPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == fhStates)
                {
                    fhRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            fhRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an fh information element
infoElem fhFuzz()
{
    infoElem fh;

    //What to return when not fuzzed
    if (fhRunningState == 0)
    {
        fh.id = 0;
        fh.len = 0;
        fh.len_data = -1;
        fh.data = "";
    }
    else
    {
        switch (fuzzState) //update this
        {
            case 0:     //255*0xff
            {
                fh.id = 2;
                fh.len = 255;
                fh.len_data = 255;
                //create data of 255 times 0xff
                u_char *data = malloc(255);
                memset(data, 0xff, 255);
                fh.data = data;
            }
            case 1:  //fh different lengths
            {
                if (fuzzStep < 16)
                {
                    int dataSize = 0 + fuzzStep;

                    fh.id = 2;
                    fh.len = dataSize;
                    fh.len_data = dataSize;
                    //create data of datasize times 0x96
                    u_char *data = malloc(dataSize);
                    if (fuzzStep % 2 == 0) //even
                        memset(data, 0x00, dataSize);
                    else //odd
                        memset(data, 0xff, dataSize);
                    fh.data = data;
                }
                else
                {
                    int dataSize = 255 - fuzzStep + 16;

                    fh.id = 2;
                    fh.len = dataSize;
                    fh.len_data = dataSize;
                    //create data of datasize times 0x96
                    u_char *data = malloc(dataSize);
                    if (fuzzStep % 2 == 0) //even
                        memset(data, 0x00, dataSize);
                    else //odd
                        memset(data, 0xff, dataSize);
                    fh.data = data;
                }
                break;
            } 
        }
    }
    
    return fh;
}
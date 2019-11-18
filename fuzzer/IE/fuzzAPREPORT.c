/*
Fuzzes ap channel report Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the apreportFuzzer is running
int apreportRunningState = 0;

//Number of fuzzing states
const int apreportStates =  4;
//Steps of fuzzers for each fuzzing state
const int apreportSteps[] =   {1, 2, 8, 8};

//Current state and step of the apreportFuzzer
int fuzzState;
int fuzzStep;

void apreportPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing apreport IE\e[39m\n");
            printf("Trying 255*0xFF data\n");
            break;
        }
        case 1: 
        {
            printf("Trying length of 1\n");
            break;
        }
        case 2: 
        {
            printf("Fuzzing large lengths with 0xFF data\n");
            break;
        }
        case 3: 
        {
            printf("Fuzzing large lengths with 0x00 data\n");
            break;
        }
        case 4:
        {
            printf("\e[33mDone with fuzzing apreport\e[39m\n");
            break;
        }
    }
}

//Updates apreportFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int apreportFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            apreportRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            apreportPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (apreportRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < apreportSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    apreportPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == apreportStates)
                {
                    apreportRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            apreportRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an apreport information element
infoElem apreportFuzz()
{
    infoElem apreport;

    //What to return when not fuzzed
    if (apreportRunningState == 0)
    {
        apreport.id = 0;
        apreport.len = 1;
        apreport.len_data = -1;
        apreport.data = "\xab";
    }
    else
    {
        switch (fuzzState) //update this
        {
            case 0:     //255*0xff
            {
                apreport.id = 51;
                apreport.len = 255;
                apreport.len_data = 255;
                //create data of 255 times 0xff
                u_char *data = malloc(255);
                memset(data, 0xff, 255);
                apreport.data = data;
                break;
            }
            case 1:  //apreport data
            {
                if (fuzzStep == 0)
                {
                    apreport.id = 51;
                    apreport.len = 1;
                    apreport.len_data = 1;
                    apreport.data = "\x00";
                }
                else
                {
                    apreport.id = 51;
                    apreport.len = 1;
                    apreport.len_data = 1;
                    apreport.data = "\xFF";
                }
                
                break;
            } 
            case 2:  //length with 0xff data
            {
                int dataSize = 255 - fuzzStep;

                apreport.id = 51;
                apreport.len = dataSize;
                apreport.len_data = dataSize;
                //create data of datasize times 0xff
                u_char *data = malloc(dataSize);
                memset(data, 0xff, dataSize);
                apreport.data = data;
                break;
            } 
            case 3:  //length with 0x00 data
            {
                int dataSize = 255 - fuzzStep;

                apreport.id = 51;
                apreport.len = dataSize;
                apreport.len_data = dataSize;
                //create data of datasize times 0x00
                u_char *data = malloc(dataSize);
                memset(data, 0x00, dataSize);
                apreport.data = data;
                break;
            } 
        }
    }
    
    return apreport;
}
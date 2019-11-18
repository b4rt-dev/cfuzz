/*
Fuzzes hopping pattern table Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the hoptableFuzzer is running
int hoptableRunningState = 0;

//Number of fuzzing states
const int hoptableStates =  4;
//Steps of fuzzers for each fuzzing state
const int hoptableSteps[] =   {1, 2, 6, 6};

//Current state and step of the hoptableFuzzer
int fuzzState;
int fuzzStep;

void hoptablePrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing hoptable IE\e[39m\n");
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
            printf("Fuzzing small lengths with 0x00 data\n");
            break;
        }
        case 3: 
        {
            printf("Fuzzing small lengths with 0xff data\n");
            break;
        }
        case 4:
        {
            printf("\e[33mDone with fuzzing hoptable\e[39m\n");
            break;
        }
    }
}

//Updates hoptableFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int hoptableFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            hoptableRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            hoptablePrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (hoptableRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < hoptableSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    hoptablePrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == hoptableStates)
                {
                    hoptableRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            hoptableRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an hoptable information element
infoElem hoptableFuzz()
{
    infoElem hoptable;

    //What to return when not fuzzed
    if (hoptableRunningState == 0)
    {
        hoptable.id = 0;
        hoptable.len = 1;
        hoptable.len_data = -1;
        hoptable.data = "\xab";
    }
    else
    {
        switch (fuzzState) //update this
        {
            case 0:     //255*0xff
            {
                hoptable.id = 9;
                hoptable.len = 255;
                hoptable.len_data = 255;
                //create data of 255 times 0xff
                u_char *data = malloc(255);
                memset(data, 0xff, 255);
                hoptable.data = data;
                break;
            }
            case 1:  //hoptable data
            {
                if (fuzzStep == 0)
                {
                    hoptable.id = 9;
                    hoptable.len = 9;
                    hoptable.len_data = 9;
                    hoptable.data = "\x00\x00\x00\x00\x00\x00\x00\x00\x00";
                }
                else
                {
                    hoptable.id = 9;
                    hoptable.len = 9;
                    hoptable.len_data = 9;
                    hoptable.data = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
                }
                
                break;
            } 
            case 2:  //length with 0xff data
            {
                int dataSize = fuzzStep;

                hoptable.id = 9;
                hoptable.len = dataSize;
                hoptable.len_data = dataSize;
                //create data of datasize times 0xff
                u_char *data = malloc(dataSize);
                memset(data, 0xff, dataSize);
                hoptable.data = data;
           
                break;
            } 
            case 3:  //length with 0x00 data
            {
                int dataSize = fuzzStep;

                hoptable.id = 9;
                hoptable.len = dataSize;
                hoptable.len_data = dataSize;
                //create data of datasize times 0x00
                u_char *data = malloc(dataSize);
                memset(data, 0x00, dataSize);
                hoptable.data = data;
           
                break;
            } 
        }
    }
    
    return hoptable;
}
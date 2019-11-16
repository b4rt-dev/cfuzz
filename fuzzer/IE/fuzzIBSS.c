/*
Fuzzes ibss Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the ibssFuzzer is running
int ibssRunningState = 0;

//Number of fuzzing states
const int ibssStates =  4;
//Steps of fuzzers for each fuzzing state
const int ibssSteps[] =   {1, 2, 16, 16};

//Current state and step of the ibssFuzzer
int fuzzState;
int fuzzStep;

void ibssPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing ibss IE\e[39m\n");
            printf("Trying 255*0xFF data\n");
            break;
        }
        case 1: 
        {
            printf("Fuzzing ATIM Window\n");
            break;
        }
        case 2: 
        {
            printf("Fuzzing lengths with 0x00 data\n");
            break;
        }
        case 3: 
        {
            printf("Fuzzing lengths with 0xFF data\n");
            break;
        }
        case 4:
        {
            printf("\e[33mDone with fuzzing ibss\e[39m\n");
            break;
        }
    }
}

//Updates ibssFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int ibssFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            ibssRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            ibssPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (ibssRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < ibssSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    ibssPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == ibssStates)
                {
                    ibssRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            ibssRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an ibss information element
infoElem ibssFuzz()
{
    infoElem ibss;

    //What to return when not fuzzed
    if (ibssRunningState == 0)
    {
        ibss.id = 0;
        ibss.len = 1;
        ibss.len_data = -1;
        ibss.data = "\xab";
    }
    else
    {
        switch (fuzzState) //update this
        {
            case 0:     //255*0xff
            {
                ibss.id = 6;
                ibss.len = 255;
                ibss.len_data = 255;
                //create data of 255 times 0xff
                u_char *data = malloc(255);
                memset(data, 0xff, 255);
                ibss.data = data;
                break;
            }
            case 1:  //ibss null data
            {
                if (fuzzStep == 0)
                {
                    ibss.id = 6;
                    ibss.len = 2;
                    ibss.len_data = 2;
                    ibss.data = "\x00\x00";
                }
                else
                {
                    ibss.id = 6;
                    ibss.len = 2;
                    ibss.len_data = 2;
                    ibss.data = "\xFF\xFF";
                }
                
                break;
            } 
            case 2:  //length with 0xff data
            {
                if (fuzzStep < 8)
                {
                    int dataSize = fuzzStep;

                    ibss.id = 6;
                    ibss.len = dataSize;
                    ibss.len_data = dataSize;
                    //create data of datasize times 0xff
                    u_char *data = malloc(dataSize);
                    memset(data, 0xff, dataSize);
                    ibss.data = data;
                }
                else
                {
                    int dataSize = 255 - fuzzStep + 8;

                    ibss.id = 6;
                    ibss.len = dataSize;
                    ibss.len_data = dataSize;
                    //create data of datasize times 0xff
                    u_char *data = malloc(dataSize);
                    memset(data, 0xff, dataSize);
                    ibss.data = data;
                }
                break;
            } 
            case 3:  //length with 0x00 data
            {
                if (fuzzStep < 8)
                {
                    int dataSize = fuzzStep;

                    ibss.id = 6;
                    ibss.len = dataSize;
                    ibss.len_data = dataSize;
                    //create data of datasize times 0x00
                    u_char *data = malloc(dataSize);
                    memset(data, 0x00, dataSize);
                    ibss.data = data;
                }
                else
                {
                    int dataSize = 255 - fuzzStep + 8;

                    ibss.id = 6;
                    ibss.len = dataSize;
                    ibss.len_data = dataSize;
                    //create data of datasize times 0x00
                    u_char *data = malloc(dataSize);
                    memset(data, 0x00, dataSize);
                    ibss.data = data;
                }
                break;
            } 
        }
    }
    
    return ibss;
}
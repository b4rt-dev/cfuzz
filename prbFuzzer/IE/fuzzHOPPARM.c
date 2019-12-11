/*
Fuzzes hopping pattern parameters Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the hopparmFuzzer is running
int hopparmRunningState = 0;

//Number of fuzzing states
const int hopparmStates =  4;
//Steps of fuzzers for each fuzzing state
const int hopparmSteps[] =   {1, 2, 16, 16};

//Current state and step of the hopparmFuzzer
int fuzzState;
int fuzzStep;

void hopparmPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing hopparm IE\e[39m\n");
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
            printf("\e[33mDone with fuzzing hopparm\e[39m\n");
            break;
        }
    }
}

//Updates hopparmFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int hopparmFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            hopparmRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            hopparmPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (hopparmRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < hopparmSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    hopparmPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == hopparmStates)
                {
                    hopparmRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            hopparmRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an hopparm information element
infoElem hopparmFuzz()
{
    infoElem hopparm;

    //What to return when not fuzzed
    if (hopparmRunningState == 0)
    {
        hopparm.id = 0;
        hopparm.len = 1;
        hopparm.len_data = -1;
        hopparm.data = "\xab";
    }
    else
    {
        switch (fuzzState) //update this
        {
            case 0:     //255*0xff
            {
                hopparm.id = 8;
                hopparm.len = 255;
                hopparm.len_data = 255;
                //create data of 255 times 0xff
                u_char *data = malloc(255);
                memset(data, 0xff, 255);
                hopparm.data = data;
                break;
            }
            case 1:  //hopparm data
            {
                if (fuzzStep == 0)
                {
                    hopparm.id = 8;
                    hopparm.len = 2;
                    hopparm.len_data = 2;
                    hopparm.data = "\x00\x00";
                }
                else
                {
                    hopparm.id = 8;
                    hopparm.len = 2;
                    hopparm.len_data = 2;
                    hopparm.data = "\xFF\xFF";
                }
                
                break;
            } 
            case 2:  //length with 0xff data
            {
                if (fuzzStep < 8)
                {
                    int dataSize = fuzzStep;

                    hopparm.id = 8;
                    hopparm.len = dataSize;
                    hopparm.len_data = dataSize;
                    //create data of datasize times 0xff
                    u_char *data = malloc(dataSize);
                    memset(data, 0xff, dataSize);
                    hopparm.data = data;
                }
                else
                {
                    int dataSize = 255 - fuzzStep + 8;

                    hopparm.id = 8;
                    hopparm.len = dataSize;
                    hopparm.len_data = dataSize;
                    //create data of datasize times 0xff
                    u_char *data = malloc(dataSize);
                    memset(data, 0xff, dataSize);
                    hopparm.data = data;
                }
                break;
            } 
            case 3:  //length with 0x00 data
            {
                if (fuzzStep < 8)
                {
                    int dataSize = fuzzStep;

                    hopparm.id = 8;
                    hopparm.len = dataSize;
                    hopparm.len_data = dataSize;
                    //create data of datasize times 0x00
                    u_char *data = malloc(dataSize);
                    memset(data, 0x00, dataSize);
                    hopparm.data = data;
                }
                else
                {
                    int dataSize = 255 - fuzzStep + 8;

                    hopparm.id = 8;
                    hopparm.len = dataSize;
                    hopparm.len_data = dataSize;
                    //create data of datasize times 0x00
                    u_char *data = malloc(dataSize);
                    memset(data, 0x00, dataSize);
                    hopparm.data = data;
                }
                break;
            } 
        }
    }
    
    return hopparm;
}
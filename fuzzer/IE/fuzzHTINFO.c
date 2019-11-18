/*
Fuzzes ht capabilities Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the htinfoFuzzer is running
int htinfoRunningState = 0;

//Number of fuzzing states
const int htinfoStates =  4;
//Steps of fuzzers for each fuzzing state
const int htinfoSteps[] =   {1, 2, 32, 32};

//Current state and step of the htinfoFuzzer
int fuzzState;
int fuzzStep;

void htinfoPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing htinfo IE\e[39m\n");
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
            printf("\e[33mDone with fuzzing htinfo\e[39m\n");
            break;
        }
    }
}

//Updates htinfoFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int htinfoFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            htinfoRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            htinfoPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (htinfoRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < htinfoSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    htinfoPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == htinfoStates)
                {
                    htinfoRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            htinfoRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an htinfo information element
infoElem htinfoFuzz()
{
    infoElem htinfo;

    //What to return when not fuzzed
    if (htinfoRunningState == 0)
    {
        htinfo.id = 0;
        htinfo.len = 1;
        htinfo.len_data = -1;
        htinfo.data = "\xab";
    }
    else
    {
        switch (fuzzState) //update this
        {
            case 0:     //255*0xff
            {
                htinfo.id = 61;
                htinfo.len = 255;
                htinfo.len_data = 255;
                //create data of 255 times 0xff
                u_char *data = malloc(255);
                memset(data, 0xff, 255);
                htinfo.data = data;
                break;
            }
            case 1:  //htinfo data
            {
                if (fuzzStep == 0)
                {
                    htinfo.id = 61;
                    htinfo.len = 1;
                    htinfo.len_data = 1;
                    htinfo.data = "\x00";
                }
                else
                {
                    htinfo.id = 61;
                    htinfo.len = 1;
                    htinfo.len_data = 1;
                    htinfo.data = "\xFF";
                }
                
                break;
            } 
            case 2:  //length with 0xff data
            {
                if (fuzzStep < 26)
                {
                    int dataSize = fuzzStep;

                    htinfo.id = 61;
                    htinfo.len = dataSize;
                    htinfo.len_data = dataSize;
                    //create data of datasize times 0xff
                    u_char *data = malloc(dataSize);
                    memset(data, 0xff, dataSize);
                    htinfo.data = data;
                }
                else
                {
                    int dataSize = 255 - fuzzStep + 26;

                    htinfo.id = 61;
                    htinfo.len = dataSize;
                    htinfo.len_data = dataSize;
                    //create data of datasize times 0xff
                    u_char *data = malloc(dataSize);
                    memset(data, 0xff, dataSize);
                    htinfo.data = data;
                }
                break;
            } 
            case 3:  //length with 0x00 data
            {
                if (fuzzStep < 26)
                {
                    int dataSize = fuzzStep;

                    htinfo.id = 61;
                    htinfo.len = dataSize;
                    htinfo.len_data = dataSize;
                    //create data of datasize times 0x00
                    u_char *data = malloc(dataSize);
                    memset(data, 0x00, dataSize);
                    htinfo.data = data;
                }
                else
                {
                    int dataSize = 255 - fuzzStep + 26;

                    htinfo.id = 61;
                    htinfo.len = dataSize;
                    htinfo.len_data = dataSize;
                    //create data of datasize times 0x00
                    u_char *data = malloc(dataSize);
                    memset(data, 0x00, dataSize);
                    htinfo.data = data;
                }
                break;
            } 
        }
    }
    
    return htinfo;
}
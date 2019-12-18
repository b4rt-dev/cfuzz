/*
Fuzzes ht capabilities Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the edcaFuzzer is running
int edcaRunningState = 0;

//Number of fuzzing states
const int edcaStates =  4;
//Steps of fuzzers for each fuzzing state
const int edcaSteps[] =   {1, 2, 32, 32};

//Current state and step of the edcaFuzzer
int fuzzState;
int fuzzStep;

void edcaPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing edca IE\e[39m\n");
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
            printf("\e[33mDone with fuzzing edca\e[39m\n");
            break;
        }
    }
}

//Updates edcaFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int edcaFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            edcaRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            edcaPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (edcaRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < edcaSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    edcaPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == edcaStates)
                {
                    edcaRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            edcaRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an edca information element
infoElem edcaFuzz()
{
    infoElem edca;

    //What to return when not fuzzed
    if (edcaRunningState == 0)
    {
        edca.id = 0;
        edca.len = 1;
        edca.len_data = -1;
        edca.data = "\xab";
    }
    else
    {
        switch (fuzzState) //update this
        {
            case 0:     //255*0xff
            {
                edca.id = 12;
                edca.len = 255;
                edca.len_data = 255;
                //create data of 255 times 0xff
                u_char *data = malloc(255);
                memset(data, 0xff, 255);
                edca.data = data;
                break;
            }
            case 1:  //edca data
            {
                if (fuzzStep == 0)
                {
                    edca.id = 12;
                    edca.len = 18;
                    edca.len_data = 18;
                    edca.data = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
                }
                else
                {
                    edca.id = 12;
                    edca.len = 18;
                    edca.len_data = 18;
                    edca.data = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
                }
                
                break;
            } 
            case 2:  //length with 0xff data
            {
                if (fuzzStep < 26)
                {
                    int dataSize = fuzzStep;

                    edca.id = 12;
                    edca.len = dataSize;
                    edca.len_data = dataSize;
                    //create data of datasize times 0xff
                    u_char *data = malloc(dataSize);
                    memset(data, 0xff, dataSize);
                    edca.data = data;
                }
                else
                {
                    int dataSize = 255 - fuzzStep + 26;

                    edca.id = 12;
                    edca.len = dataSize;
                    edca.len_data = dataSize;
                    //create data of datasize times 0xff
                    u_char *data = malloc(dataSize);
                    memset(data, 0xff, dataSize);
                    edca.data = data;
                }
                break;
            } 
            case 3:  //length with 0x00 data
            {
                if (fuzzStep < 26)
                {
                    int dataSize = fuzzStep;

                    edca.id = 12;
                    edca.len = dataSize;
                    edca.len_data = dataSize;
                    //create data of datasize times 0x00
                    u_char *data = malloc(dataSize);
                    memset(data, 0x00, dataSize);
                    edca.data = data;
                }
                else
                {
                    int dataSize = 255 - fuzzStep + 26;

                    edca.id = 12;
                    edca.len = dataSize;
                    edca.len_data = dataSize;
                    //create data of datasize times 0x00
                    u_char *data = malloc(dataSize);
                    memset(data, 0x00, dataSize);
                    edca.data = data;
                }
                break;
            } 
        }
    }
    
    return edca;
}
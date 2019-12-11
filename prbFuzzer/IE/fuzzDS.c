/*
Fuzzes DS Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the dsFuzzer is running
int dsRunningState = 0;

//Number of fuzzing states
const int dsStates =  3;
//Steps of fuzzers for each fuzzing state
const int dsSteps[] =   {1, 32, 32};

//Current state and step of the dsFuzzer
int fuzzState;
int fuzzStep;

void dsPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing DS IE\e[39m\n");
            printf("Trying 255*0xFF data\n");
            break;
        }
        case 1: 
        {
            printf("Trying other lengths than 1\n");
            break;
        }
        case 2: 
        {
            printf("Fuzzing channel number\n");
            break;
        }
        case 3:
        {
            printf("\e[33mDone with fuzzing ds\e[39m\n");
            break;
        }
    }
}

//Updates dsFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int dsFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            dsRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            dsPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (dsRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < dsSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    dsPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == dsStates)
                {
                    dsRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            dsRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an ds information element
infoElem dsFuzz()
{
    infoElem ds;

    //What to return when not fuzzed
    if (dsRunningState == 0)
    {
        ds.id = 3;
        ds.len = 1;
        ds.len_data = 1;
        ds.data = "\x01";
    }
    else
    {
        switch (fuzzState)
        {
            case 0:     //255*0xff
            {
                ds.id = 3;
                ds.len = 255;
                ds.len_data = 255;
                //create data of 255 times 0xff
                u_char *data = malloc(255);
                memset(data, 0xff, 255);
                ds.data = data;
                break;
            }
            case 1:  //lengths
            {
                if (fuzzStep < 16)
                {
                    int dataSize = 2 + fuzzStep;

                    ds.id = 3;
                    ds.len = dataSize;
                    ds.len_data = dataSize;
                    //create data of datasize times 0x01
                    u_char *data = malloc(dataSize);
                    memset(data, 0x01, dataSize);
                    ds.data = data;
                }
                else
                {
                    int dataSize = 255 - fuzzStep + 16;

                    ds.id = 3;
                    ds.len = dataSize;
                    ds.len_data = dataSize;
                    //create data of datasize times 0x01
                    u_char *data = malloc(dataSize);
                    memset(data, 0x01, dataSize);
                    ds.data = data;
                }
                break;
            } 
            case 2:  //channel number
            {
                ds.id = 3;
                ds.len = 1;
                ds.len_data = 1;

                if (fuzzStep == 0)
                    ds.data = "\x00";
                else
                {
                    u_char *data = malloc(1);
                    memset(data, 256 - fuzzStep, 1);
                    ds.data = data;
                }
                break;
            } 
        }
    }
    
    return ds;
}
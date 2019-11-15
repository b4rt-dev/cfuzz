/*
Fuzzes Supported TIM Information element
Files to change when adding subfuzzer:
- fuzzer.c with includes
- frameCreator.c with includes
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the timFuzzer is running
int timRunningState = 0;

//Number of fuzzing states
const int timStates =  3;  
//Steps of fuzzers for each fuzzing state
const int timSteps[] =   {1, 8, 32}; 

//Current state and step of the timFuzzer
int fuzzState;
int fuzzStep;

void timPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing TIM IE\e[39m\n");
            printf("Trying 255*0xFF data\n");
            break;
        }
        case 1: 
        {
            printf("Fuzzing short lengths\n");
            break;
        }
        case 2: 
        {
            printf("Fuzzing values\n");
            break;
        }
        case 3:
        {
            printf("\e[33mDone with fuzzing tim\e[39m\n");
            break;
        }
    }
}

//Updates timFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int timFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            timRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            timPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (timRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < timSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    timPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == timStates)
                {
                    timRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            timRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an tim information element
infoElem timFuzz()
{
    infoElem tim;

    //What to return when not fuzzed
    if (timRunningState == 0) //update this
    {
        tim.id = 0;
        tim.len = 1;
        tim.len_data = -1;
        tim.data = "\xab";
    }
    else
    {
        switch (fuzzState)
        {
            case 0:     //255*0xff
            {
                tim.id = 5; 
                tim.len = 255;
                tim.len_data = 255;
                //create data of 255 times 0xff
                u_char *data = malloc(255);
                memset(data, 0xff, 255);
                tim.data = data;
                break;
            }
            case 1:  //tim short lengths
            {
                int dataSize = 0 + fuzzStep;

                tim.id = 5; 
                tim.len = dataSize;
                tim.len_data = dataSize;
                //create data of datasize times 0xFF
                u_char *data = malloc(dataSize);
                memset(data, 0xFF, dataSize);
                tim.data = data;
                break;
            } 
            case 2:  //tim values
            {
                int dataSize = 255;

                tim.id = 5; 
                tim.len = dataSize;
                tim.len_data = dataSize;
                //create data of datasize times 0xFF
                u_char *data = malloc(dataSize);
                if (fuzzStep < 16)
                    memset(data, fuzzStep, dataSize);
                else
                    memset(data, 255 + 16 - fuzzStep, dataSize);
                tim.data = data;
                break;
            } 
        }
    }
    
    return tim;
}
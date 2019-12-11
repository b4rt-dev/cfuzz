/*
Fuzzes request Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the requestFuzzer is running
int requestRunningState = 0;

//Number of fuzzing states
const int requestStates =  2;
//Steps of fuzzers for each fuzzing state
const int requestSteps[] =   {1, 2};

//Current state and step of the requestFuzzer
int fuzzState;
int fuzzStep;

void requestPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing request IE\e[39m\n");
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
            printf("\e[33mDone with fuzzing request\e[39m\n");
            break;
        }
    }
}

//Updates requestFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int requestFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            requestRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            requestPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (requestRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < requestSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    requestPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == requestStates)
                {
                    requestRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            requestRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an request information element
infoElem requestFuzz()
{
    infoElem request;

    //What to return when not fuzzed
    if (requestRunningState == 0)
    {
        request.id = 0;
        request.len = 1;
        request.len_data = -1;
        request.data = "\xab";
    }
    else
    {
        switch (fuzzState) //update this
        {
            case 0:     //255*0xff
            {
                request.id = 10;
                request.len = 255;
                request.len_data = 255;
                //create data of 255 times 0xff
                u_char *data = malloc(255);
                memset(data, 0xff, 255);
                request.data = data;
                break;
            }
            case 1:  //request data
            {
                if (fuzzStep == 0)
                {
                    request.id = 10;
                    request.len = 9;
                    request.len_data = 9;
                    request.data = "\x00\x01\x02\x03\x04\x0A\x0A\xBC\x0BE";
                }
                else
                {
                    request.id = 10;
                    request.len = 9;
                    request.len_data = 9;
                    request.data = "\xFF\xFF\xFF\x00\x00\xFF\xFF\xFF\xFF";
                }
                
                break;
            } 
        }
    }
    
    return request;
}
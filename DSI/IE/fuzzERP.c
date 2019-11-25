/*
Fuzzes erp Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the erpFuzzer is running
int erpRunningState = 0;

//Number of fuzzing states
const int erpStates =  1;
//Steps of fuzzers for each fuzzing state
const int erpSteps[] =   {10};

//Current state and step of the erpFuzzer
int fuzzState;
int fuzzStep;

void erpPrintCurrentState()
{
    
}

//Updates erpFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int erpFuzzUpdate(int status)
{
    fuzzState = 0;
    if (fuzzStep == 0)
        fuzzStep = 1;
    else
        fuzzStep = 0;

    return 0;
}

//Returns an erp information element
infoElem erpFuzz()
{
    infoElem erp;

    //What to return when not fuzzed
    if (fuzzStep == 0)
    {
        int dataSize = 10;

        erp.id = 42;
        erp.len = dataSize;
        erp.len_data = dataSize;
        //create data of datasize times 0xff
        u_char *data = malloc(dataSize);
        memset(data, 0xff, dataSize);
        erp.data = data;   
    }
    else
    {   
        int dataSize = 253;

        erp.id = 42;
        erp.len = dataSize;
        erp.len_data = dataSize;
        //create data of datasize times 0xff
        u_char *data = malloc(dataSize);
        memset(data, 0xff, dataSize);
        erp.data = data;   
    }
    return erp;
}
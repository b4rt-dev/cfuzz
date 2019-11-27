/*
Fuzzes SSID Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "../frameDefinitions.h"

//Indecates whether the ssidFuzzer is running
int ssidRunningState = 0;

//Number of fuzzing states
const int ssidStates =  1;
//Steps of fuzzers for each fuzzing state
const int ssidSteps[] =   {256};

//Current state and step of the ssidFuzzer
int fuzzState;
int fuzzStep;

void ssidPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing SSID IE\e[39m\n");
            printf("SSID name counter\n");
            break;
        }
        case 1:
        {
            printf("\e[33mDone with SSID IE\e[39m\n");
            break;
        }
    }
}

//Updates ssidFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int ssidFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            ssidRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            ssidPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (ssidRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < ssidSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    ssidPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == ssidStates)
                {
                    ssidRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            ssidRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an SSID information element
infoElem ssidFuzz()
{
    infoElem ssid;

    //What to return when not fuzzed
    //We do not return an SSID, because of the experiment
    if (ssidRunningState == 0)
    {
        ssid.id = 0;
        ssid.len = 4;
        ssid.len_data = -1;
        ssid.data = "\x46\x55\x5a\x5a";
    }
    else
    {
        switch (fuzzState)
        {
            case 0: //SSID incorrect length with data
            {
                int i;
                if (fuzzStep == 0)
                    i = 1;
                else
                    i = floor(log10(abs(fuzzStep))) + 1;

                //printf("SSID := %d\n", fuzzStep);

                ssid.id = 0;
                ssid.len = i;
                ssid.len_data = i;

                u_char *buffer = malloc(32);
                sprintf(buffer,"%d", fuzzStep);

                ssid.data = buffer;
                break;
            }
        }

    }
    

    return ssid;
}
/*
Fuzzes SSID Information element

TODO
- free after malloc (actually, find a better alternative for malloc)
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the ssidFuzzer is running
int ssidRunningState = 0;

//Number of fuzzing states
const int ssidStates =  4;
//Steps of fuzzers for each fuzzing state
const int ssidSteps[] =   {45, 45, 16, 256};

//Current state and step of the ssidFuzzer
int fuzzState;
int fuzzStep;

void ssidPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("Fuzzing SSID incorrect length with data\n");
            break;
        }
        case 1: 
        {
            printf("Fuzzing SSID incorrect length without data\n");
            break;
        }
        case 2: 
        {
            printf("Fuzzing SSID oversized length\n");
            break;
        }
        case 3: 
        {
            printf("Fuzzing SSID characters\n");
            break;
        }
        case 4:
        {
            printf("Done with fuzzing SSID\n");
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
                if (fuzzStep < ssidSteps[fuzzState])
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
    //We do return an SSID, because it is required
    if (ssidRunningState == 0)
    {
        ssid.id = 0;
        ssid.len = 4;
        ssid.len_data = 4;
        ssid.data = "\x46\x55\x5a\x5a";
    }
    else
    {
        switch (fuzzState)
        {
            case 0: //SSID incorrect length with data
            {
                if (fuzzStep <= 38)
                {
                    ssid.id = 0;
                    ssid.len = fuzzStep;
                    ssid.len_data = 4;
                    ssid.data = "\x46\x55\x5a\x5a";
                }
                else
                {
                    ssid.id = 0;
                    ssid.len = 255 - (fuzzStep - 39);
                    ssid.len_data = 4;
                    ssid.data = "\x46\x55\x5a\x5a";
                }
                break;
            }
            case 1: //SSID incorrect length without data
            {
                if (fuzzStep <= 38)
                {
                    ssid.id = 0;
                    ssid.len = fuzzStep;
                    ssid.len_data = 0;
                    ssid.data = "";
                }
                else
                {
                    ssid.id = 0;
                    ssid.len = 255 - (fuzzStep - 39);
                    ssid.len_data = 0;
                    ssid.data = "";
                }
                break;
            }
            case 2: //SSID oversized length
            {
                if (fuzzStep < 8)
                {
                    int dataSize = 33 + fuzzStep;

                    ssid.id = 0;
                    ssid.len = dataSize;
                    ssid.len_data = dataSize;
                    //create data of datasize times 0x61
                    u_char *data = malloc(dataSize);
                    memset(data, 0x61, dataSize);
                    ssid.data = data;
                }
                else
                {
                    int dataSize = 255 - fuzzStep;

                    ssid.id = 0;
                    ssid.len = dataSize;
                    ssid.len_data = dataSize;
                    //create data of datasize times 0x61
                    u_char *data = malloc(dataSize);
                    memset(data, 0x61, dataSize);
                    ssid.data = data;
                }
                break;
            }
            case 3:  //SSID characters
            {
                ssid.id = 0;
                ssid.len = 32;
                ssid.len_data = 32;
                //create characters
                u_char *data = malloc(32);
                for (int i = 0; i < 32; i++)
                {
                    data[i] = fuzzStep;
                }
                ssid.data = data;
                break;
            } 
        }

    }
    

    return ssid;
}
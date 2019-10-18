/*
Manages what to fuzz when.

TODO
- free after malloc
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "fuzzer.h"
#include "frameDefinitions.h"

//Current (initial) state and step of the fuzzer
unsigned long fuzzState     = 0;
unsigned long fuzzStep      = 0;

//Steps of fuzzers for each state
int states[] = {0,1,2,3};
int steps[] = {45,45,16,256};

//Controls state of fuzzer, and therefore what to fuzz next
void increaseFuzzer()
{
    if (fuzzState >= 4)
    {
        printf("Done with Fuzzing\n");
        exit(0);
    }
    else
    {
        if (fuzzStep == 0)
        {
            switch (fuzzState) //These messages are only printed when a frame is received
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
            }
        }
        if (fuzzStep < steps[fuzzState])
            fuzzStep = fuzzStep + 1;
        else
        {
            fuzzStep = 0;
            fuzzState = fuzzState + 1;
        }
    }

}

int getFuzzState()
{
    return fuzzState;
}

int getFuzzStep()
{
    return fuzzStep;
}

//Returns an SSID information element
infoElem ssidFuzz()
{
    infoElem ssid = {
            0,         //id
            4,         //len
            4,         //real length of data
            "\x46\x55\x5a\x5a" //data
            };

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
    

    return ssid;
}
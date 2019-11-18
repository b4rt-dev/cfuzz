/*
Fuzzes rsn Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the rsnFuzzer is running
int rsnRunningState = 0;

//Number of fuzzing states
const int rsnStates =  7;
//Steps of fuzzers for each fuzzing state
const int rsnSteps[] =   {1, 4, 8, 8, 8, 8, 32};

//Current state and step of the rsnFuzzer
int fuzzState;
int fuzzStep;

void rsnPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing rsn IE\e[39m\n");
            printf("Trying 255*0xFF data\n");
            break;
        }
        case 1: 
        {
            printf("All 0xff or 0x00 except version field\n");
            break;
        }
        case 2: 
        {
            printf("Fuzzing version field\n");
            break;
        }
        case 3: 
        {
            printf("Fuzzing Pairwise Cipher Suite Count field\n");
            break;
        }
        case 4: 
        {
            printf("Fuzzing AKM Suite Count field\n");
            break;
        }
        case 5: 
        {
            printf("Fuzzing PMKID Count field\n");
            break;
        }
        case 6: 
        {
            printf("Fuzzing small lengths\n");
            break;
        }
        case 7:
        {
            printf("\e[33mDone with fuzzing rsn\e[39m\n");
            break;
        }
    }
}

//Updates rsnFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int rsnFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            rsnRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            rsnPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (rsnRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < rsnSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    rsnPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == rsnStates)
                {
                    rsnRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            rsnRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an rsn information element
infoElem rsnFuzz()
{
    infoElem rsn;

    //What to return when not fuzzed
    if (rsnRunningState == 0)
    {
        rsn.id = 0;
        rsn.len = 1;
        rsn.len_data = -1;
        rsn.data = "\xab";
    }
    else
    {
        switch (fuzzState) //update this
        {
            case 0:     //255*0xff
            {
                rsn.id = 48;
                rsn.len = 255;
                rsn.len_data = 255;
                //create data of 255 times 0xff
                u_char *data = malloc(255);
                memset(data, 0xff, 255);
                rsn.data = data;
                break;
            }
            case 1:
            {
                if (fuzzStep < 2)
                {
                    rsn.id = 48;
                    rsn.len = 255;
                    rsn.len_data = 255;
                    //create data of 255 times 0xff
                    u_char *data = malloc(255);
                    memset(data, 0xff, 255);
                    data[0] = 0x01;
                    data[1] = 0x00;
                    rsn.data = data;
                }
                else
                {
                    rsn.id = 48;
                    rsn.len = 255;
                    rsn.len_data = 255;
                    //create data of 255 times 0xff
                    u_char *data = malloc(255);
                    memset(data, 0x00, 255);
                    data[0] = 0x01;
                    data[1] = 0x00;
                    rsn.data = data;
                }
                break;
            } 
            case 2:
            {
                if (fuzzStep < 4)
                {
                    rsn.id = 48;
                    rsn.len = 24;
                    rsn.len_data = 24;
                    u_char *data = malloc(24);
                    u_char *valid = "\x01\x00\x00\x0f\xac\x02\x02\x00\x00\x0f\xac\x02\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00";
                    memcpy(data, valid, 24);
                    data[0] = fuzzStep;
                    data[1] = 0x00;
                    rsn.data = data;
                }
                else
                {
                    rsn.id = 48;
                    rsn.len = 24;
                    rsn.len_data = 24;
                    u_char *data = malloc(24);
                    u_char *valid = "\x01\x00\x00\x0f\xac\x02\x02\x00\x00\x0f\xac\x02\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00";
                    memcpy(data, valid, 24);
                    data[0] = 0xFF;
                    data[1] = 255 - fuzzStep;
                    rsn.data = data;
                }
                break;
            } 
            case 3:
            {
                if (fuzzStep < 4)
                {
                    rsn.id = 48;
                    rsn.len = 24;
                    rsn.len_data = 24;
                    u_char *data = malloc(24);
                    u_char *valid = "\x01\x00\x00\x0f\xac\x02\x02\x00\x00\x0f\xac\x02\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00";
                    memcpy(data, valid, 24);
                    data[6] = fuzzStep;
                    data[7] = 0x00;
                    rsn.data = data;
                }
                else
                {
                    rsn.id = 48;
                    rsn.len = 24;
                    rsn.len_data = 24;
                    u_char *data = malloc(24);
                    u_char *valid = "\x01\x00\x00\x0f\xac\x02\x02\x00\x00\x0f\xac\x02\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00";
                    memcpy(data, valid, 24);
                    data[6] = 0xFF;
                    data[7] = 255 - fuzzStep;
                    rsn.data = data;
                }
                break;
            } 
            case 4:
            {
                if (fuzzStep < 4)
                {
                    rsn.id = 48;
                    rsn.len = 24;
                    rsn.len_data = 24;
                    u_char *data = malloc(24);
                    u_char *valid = "\x01\x00\x00\x0f\xac\x02\x02\x00\x00\x0f\xac\x02\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00";
                    memcpy(data, valid, 24);
                    data[16] = fuzzStep;
                    data[17] = 0x00;
                    rsn.data = data;
                }
                else
                {
                    rsn.id = 48;
                    rsn.len = 24;
                    rsn.len_data = 24;
                    u_char *data = malloc(24);
                    u_char *valid = "\x01\x00\x00\x0f\xac\x02\x02\x00\x00\x0f\xac\x02\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00";
                    memcpy(data, valid, 24);
                    data[16] = 0xFF;
                    data[17] = 255 - fuzzStep;
                    rsn.data = data;
                }
                break;
            } 
            case 5:
            {
                if (fuzzStep < 4)
                {
                    rsn.id = 48;
                    rsn.len = 26;
                    rsn.len_data = 26;
                    u_char *data = malloc(26);
                    u_char *valid = "\x01\x00\x00\x0f\xac\x02\x02\x00\x00\x0f\xac\x02\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00\x00\x00";
                    memcpy(data, valid, 26);
                    data[24] = fuzzStep;
                    data[25] = 0x00;
                    rsn.data = data;
                }
                else
                {
                    rsn.id = 48;
                    rsn.len = 26;
                    rsn.len_data = 26;
                    u_char *data = malloc(26);
                    u_char *valid = "\x01\x00\x00\x0f\xac\x02\x02\x00\x00\x0f\xac\x02\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00\x00\x00";
                    memcpy(data, valid, 26);
                    data[24] = 0xFF;
                    data[25] = 255 - fuzzStep;
                    rsn.data = data;
                }
                break;
            } 
            case 6:
            {
                int dataSize = fuzzStep;

                rsn.id = 48;
                rsn.len = dataSize;
                rsn.len_data = dataSize;
                //create data of datasize times 0x00
                u_char *data = malloc(dataSize);
                memset(data, 0xFF, dataSize);
                if (dataSize >= 2)
                {
                    data[0] = 0x01;
                    data[1] = 0x00;
                }
                rsn.data = data;
                break;
            } 
        }
    }
    
    return rsn;
}
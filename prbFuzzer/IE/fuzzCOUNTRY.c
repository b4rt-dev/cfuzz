/*
Fuzzes country Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the countryFuzzer is running
int countryRunningState = 0;

//Number of fuzzing states
const int countryStates =  6;
//Steps of fuzzers for each fuzzing state
const int countrySteps[] =   {1, 6, 256, 1, 1, 1};

//Current state and step of the countryFuzzer
int fuzzState;
int fuzzStep;

void countryPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing country IE\e[39m\n");
            printf("Trying 255*0xFF data\n");
            break;
        }
        case 1: 
        {
            printf("Fuzzing lengths lower than 6\n");
            break;
        }
        case 2: 
        {
            printf("Fuzzing country string\n");
            break;
        }
        case 3: 
        {
            printf("Fuzzing first channel number, number of channels and transmit power\n");
            break;
        }
        case 4: 
        {
            printf("Ignoring padding\n");
            break;
        }
        case 5: 
        {
            printf("Trying duplicate triplets and long size without padding\n");
            break;
        }
        case 6:
        {
            printf("\e[33mDone with fuzzing country\e[39m\n");
            break;
        }
    }
}

//Updates countryFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int countryFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            countryRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            countryPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (countryRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < countrySteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    countryPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == countryStates)
                {
                    countryRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            countryRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an country information element
infoElem countryFuzz()
{
    infoElem country;

    //What to return when not fuzzed
    if (countryRunningState == 0)
    {
        country.id = 0;
        country.len = 1;
        country.len_data = -1;
        country.data = "\xab";
    }
    else
    {
        switch (fuzzState) //update this
        {
            case 0:     //255*0xff
            {
                country.id = 7;
                country.len = 255;
                country.len_data = 255;
                //create data of 255 times 0xff
                u_char *data = malloc(255);
                memset(data, 0xff, 255);
                country.data = data;
                break;
            }
            case 1:  //lengths lower than 6
            {
                int dataSize = fuzzStep;

                country.id = 7;
                country.len = dataSize;
                country.len_data = dataSize;
                //create data of datasize times 0x41
                u_char *data = malloc(dataSize);
                memset(data, 0x41, dataSize);
                country.data = data;
                break;
            } 
            case 2:  //country string
            {
                country.id = 7;
                country.len = 6;
                country.len_data = 6;
                //create characters
                u_char *data = malloc(6);
                data[0] = fuzzStep;
                data[1] = fuzzStep;
                data[2] = fuzzStep;
                data[3] = 0x01;
                data[4] = 0x0d;
                data[5] = 0x14;
                country.data = data;
                break;
            } 
            case 3:     //first channel number and number of channels
            {
                country.id = 7;
                country.len = 28;
                country.len_data = 28;
                country.data = "\x45\x55\x20" //country string
                                "\x00\x00\x00"
                                "\xff\x00\x00"
                                "\x00\xff\x00"
                                "\xff\xff\x00"
                                "\x00\x00\xff"
                                "\xff\x00\xff"
                                "\x00\xff\xff"
                                "\xff\xff\xff"
                                "\x00"; //padding
                break;
            }
            case 4:     //first channel number and number of channels
            {
                country.id = 7;
                country.len = 27;
                country.len_data = 27;
                country.data = "\x45\x55\x20" //country string
                                "\x00\x00\x00"
                                "\xff\x00\x00"
                                "\x00\xff\x00"
                                "\xff\xff\x00"
                                "\x00\x00\xff"
                                "\xff\x00\xff"
                                "\x00\xff\xff"
                                "\xff\xff\xff";
                break;
            }
            case 5:     //duplicate tiplets
            {
                country.id = 7;
                country.len = 255;
                country.len_data = 255;
                country.data = "\x45\x55\x20" //country string
                                "\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14"
                                "\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14"
                                "\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14"
                                "\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14"
                                "\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14"
                                "\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14"
                                "\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14"
                                "\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14"
                                "\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14"
                                "\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14"
                                "\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14"
                                "\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14"
                                "\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14"
                                "\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14"
                                "\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14"
                                "\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14"
                                "\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14"
                                "\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14"
                                "\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14"
                                "\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14"
                                "\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14\x01\x0d\x14";
                break;
            }
        }
    }
    
    return country;
}
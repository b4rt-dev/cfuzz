/*
Fuzzes Supported rates Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the ratesFuzzer is running
int ratesRunningState = 0;

//Number of fuzzing states
const int ratesStates =  5;
//Steps of fuzzers for each fuzzing state
const int ratesSteps[] =   {2, 4, 32, 32, 1};

//Current state and step of the ratesFuzzer
int fuzzState;
int fuzzStep;

void ratesPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("Trying rates with zero length or no element\n");
            break;
        }
        case 1: 
        {
            printf("Fuzzing duplicate rates\n");
            break;
        }
        case 2: 
        {
            printf("Fuzzing all possible rates\n");
            break;
        }
        case 3: 
        {
            printf("Fuzzing more than 8 rates\n");
            break;
        }
        case 4:
        {
            printf("Trying 255*0xFF data\n");
            break;
        }
        case 5:
        {
            printf("Done with fuzzing rates\n");
            break;
        }
    }
}

//Updates ratesFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int ratesFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            ratesRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            ratesPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (ratesRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < ratesSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    ratesPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == ratesStates)
                {
                    ratesRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            ratesRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an rates information element
infoElem ratesFuzz()
{
    infoElem rates;

    //What to return when not fuzzed
    //Since this is a mandatory frame, we do want to return a normal information element here
    if (ratesRunningState == 0)
    {
        rates.id = 1;
        rates.len = 7;
        rates.len_data = 7;
        rates.data = "\x96\x18\x24\x30\x48\x60\x6c";
    }
    else
    {
        switch (fuzzState)
        {
            case 0: //no rates or no data
            {
                if (fuzzStep == 0)
                {
                    rates.id = 1;
                    rates.len = 0;
                    rates.len_data = 0;
                    rates.data = "";
                }
                else if (fuzzStep == 1)
                {
                    rates.id = 1;
                    rates.len = 0;
                    rates.len_data = -1;
                    rates.data = "";
                }
                
                break;
            }
            case 1:  //duplicate rates
            {
                rates.id = 1;
                rates.len = 8;
                rates.len_data = 8;
                rates.data = "";
                switch (fuzzStep)
                {
                    case 0: rates.data = "\x96\x96\x96\x30\x30\x30\x30\x96"; break;
                    case 1: rates.data = "\x16\x16\x16\xB0\xB0\xB0\xB0\x16"; break;
                    case 2: rates.data = "\x02\x82\x02\x30\xB0\x30\xB0\x82"; break;
                    case 3: rates.data = "\x00\x00\x80\x80\xff\x7f\xff\x7f"; break;
                }
                break;
            } 
            case 2:  //all possible rates
            {
                rates.id = 1;
                rates.len = 8;
                rates.len_data = 8;
                u_char *data = malloc(8);
                data[0]= fuzzStep*8+0;
                data[1]= fuzzStep*8+1;
                data[2]= fuzzStep*8+2;
                data[3]= fuzzStep*8+3;
                data[4]= fuzzStep*8+4;
                data[5]= fuzzStep*8+5;
                data[6]= fuzzStep*8+6;
                data[7]= fuzzStep*8+7;
                rates.data = data;
                break;
            } 
            case 3:  //more than 8 rates
            {
                if (fuzzStep < 16)
                {
                    int dataSize = 8 + fuzzStep;

                    rates.id = 1;
                    rates.len = dataSize;
                    rates.len_data = dataSize;
                    //create data of datasize times 0x96
                    u_char *data = malloc(dataSize);
                    memset(data, 0x96, dataSize);
                    rates.data = data;
                }
                else
                {
                    int dataSize = 255 - fuzzStep + 16;

                    rates.id = 1;
                    rates.len = dataSize;
                    rates.len_data = dataSize;
                    //create data of datasize times 0x96
                    u_char *data = malloc(dataSize);
                    memset(data, 0x96, dataSize);
                    rates.data = data;
                }
                break;
            } 
            case 4:     //255*0xff
            {
                rates.id = 1;
                rates.len = 255;
                rates.len_data = 255;
                //create data of 255 times 0xff
                u_char *data = malloc(255);
                memset(data, 0xff, 255);
                rates.data = data;
            }
        }
    }
    
    return rates;
}
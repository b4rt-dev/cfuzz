/*
Fuzzes extended supported rates Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the extratesFuzzer is running
int extratesRunningState = 0;

//Number of fuzzing states
const int extratesStates =  5;
//Steps of fuzzers for each fuzzing state
const int extratesSteps[] =   {2, 4, 32, 32, 1};

//Current state and step of the extratesFuzzer
int fuzzState;
int fuzzStep;

void extratesPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing extended rates IE\e[39m\n");
            printf("Trying extrates with zero length or no element\n");
            break;
        }
        case 1: 
        {
            printf("Fuzzing duplicate ext rates\n");
            break;
        }
        case 2: 
        {
            printf("Fuzzing all possible ext rates\n");
            break;
        }
        case 3: 
        {
            printf("Fuzzing large number of ext rates\n");
            break;
        }
        case 4:
        {
            printf("Trying 255*0xFF data\n");
            break;
        }
        case 5:
        {
            printf("\e[33mDone with fuzzing extended rates IE\e[39m\n");
            break;
        }
    }
}

//Updates extratesFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int extratesFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            extratesRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            extratesPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (extratesRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < extratesSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    extratesPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == extratesStates)
                {
                    extratesRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            extratesRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an extrates information element
infoElem extratesFuzz()
{
    infoElem extrates;

    //What to return when not fuzzed
    if (extratesRunningState == 0)
    {
        extrates.id = 0;
        extrates.len = 0;
        extrates.len_data = -1;
        extrates.data = "";
    }
    else
    {
        switch (fuzzState)
        {
            case 0: //no extrates or no data
            {
                if (fuzzStep == 0)
                {
                    extrates.id = 50;
                    extrates.len = 0;
                    extrates.len_data = 0;
                    extrates.data = "";
                }
                else if (fuzzStep == 1)
                {
                    extrates.id = 50;
                    extrates.len = 0;
                    extrates.len_data = -1;
                    extrates.data = "";
                }
                
                break;
            }
            case 1:  //duplicate extrates
            {
                extrates.id = 50;
                extrates.len = 8;
                extrates.len_data = 8;
                extrates.data = "";
                switch (fuzzStep)
                {
                    case 0: extrates.data = "\x96\x96\x96\x30\x30\x30\x30\x96"; break;
                    case 1: extrates.data = "\x16\x16\x16\xB0\xB0\xB0\xB0\x16"; break;
                    case 2: extrates.data = "\x02\x82\x02\x30\xB0\x30\xB0\x82"; break;
                    case 3: extrates.data = "\x00\x00\x80\x80\xff\x7f\xff\x7f"; break;
                }
                break;
            } 
            case 2:  //all possible extrates
            {
                extrates.id = 50;
                extrates.len = 8;
                extrates.len_data = 8;
                u_char *data = malloc(8);
                data[0]= fuzzStep*8+0;
                data[1]= fuzzStep*8+1;
                data[2]= fuzzStep*8+2;
                data[3]= fuzzStep*8+3;
                data[4]= fuzzStep*8+4;
                data[5]= fuzzStep*8+5;
                data[6]= fuzzStep*8+6;
                data[7]= fuzzStep*8+7;
                extrates.data = data;
                break;
            } 
            case 3:  //many rates
            {
                int dataSize = 255 - fuzzStep;

                extrates.id = 50;
                extrates.len = dataSize;
                extrates.len_data = dataSize;
                //create data of datasize times 0x96
                u_char *data = malloc(dataSize);
                memset(data, 0x96, dataSize);
                extrates.data = data;

                break;
            } 
            case 4:     //255*0xff
            {
                extrates.id = 50;
                extrates.len = 255;
                extrates.len_data = 255;
                //create data of 255 times 0xff
                u_char *data = malloc(255);
                memset(data, 0xff, 255);
                extrates.data = data;
                break;
            }
        }
    }
    
    return extrates;
}
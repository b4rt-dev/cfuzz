/*
Fuzzes Association response Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "frameDefinitions.h"
#include "ASSieid.h"
#include "ASSoversize.h"
#include "ASSduplicate.h"
#include "ASSallies.h"
#include "ASSstatic.h"

//Indecates whether the AssRespFuzzer is running
int AssRespRunningState = 0;

//Number of fuzzing states
const int AssRespStates =  5;
//Steps of fuzzers for each fuzzing state
const int AssRespSteps[] =   {256*4, 16, 16, 4, 4};

//Current state and step of the AssRespFuzzer
int fuzzState;
int fuzzStep;

void AssRespPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing AssResp Generic stuff\e[39m\n");
            printf("Trying basic overflows on all possible IEs\n");
            break;
        }
        case 1:
        {
            printf("Fuzzing frame body length\n");
            break;
        }
        case 2:
        {
            printf("Fuzzing duplicate elements\n");
            break;
        }
        case 3:
        {
            printf("Fuzzing all ies at the same time\n");
            break;
        }
        case 4:
        {
            printf("Fuzzing static elements\n");
            break;
        }
        case 5:
        {
            printf("\e[33mDone with fuzzing AssResp\e[39m\n");
            break;
        }
    }
}

//Updates AssRespFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int AssRespFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            AssRespRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            AssRespPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (AssRespRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < AssRespSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    AssRespPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == AssRespStates)
                {
                    AssRespRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            AssRespRunningState = 0;
            break;
        }
    }
    return 0;
}


//Creates Probe response frame
u_char *AssRespFuzz(u_char *dstAddress, int *packetSize, u_char * radioTapHeader, u_char *myMAC)
{

    switch(fuzzState)
    {
        case 0:
        {
            return Assieid(dstAddress, packetSize, radioTapHeader, myMAC, fuzzStep);
            break;
        }
        case 1:
        {
            return Assoversize(dstAddress, packetSize, radioTapHeader, myMAC, fuzzStep);
            break;
        }
        case 2:
        {
            return Assduplicate(dstAddress, packetSize, radioTapHeader, myMAC, fuzzStep);
            break;
        }
        case 3:
        {
            return Assallies(dstAddress, packetSize, radioTapHeader, myMAC, fuzzStep);
            break;
        }
        case 4:
        {
            return Assstatic(dstAddress, packetSize, radioTapHeader, myMAC, fuzzStep);
            break;
        }
    }
    //return packet
    return NULL;    
}
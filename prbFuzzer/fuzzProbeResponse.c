/*
Fuzzes PrbResp Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "frameDefinitions.h"
#include "PRBieid.h"
#include "PRBflags.h"
#include "PRBoversize.h"
#include "PRBduplicate.h"
#include "PRBallies.h"

//Indecates whether the PrbRespFuzzer is running
int PrbRespRunningState = 0;

//Number of fuzzing states
const int PrbRespStates =  5;
//Steps of fuzzers for each fuzzing state
const int PrbRespSteps[] =   {256*4, 256, 16, 16, 4};

//Current state and step of the PrbRespFuzzer
int fuzzState;
int fuzzStep;

void PrbRespPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing PrbResp Generic stuff\e[39m\n");
            printf("Trying basic overflows on all possible IEs\n");
            break;
        }
        case 1: 
        {
            printf("Fuzzing flags\n");
            break;
        }
        case 2:
        {
            printf("Fuzzing frame body length\n");
            break;
        }
        case 3:
        {
            printf("Fuzzing duplicate elements\n");
            break;
        }
        case 4:
        {
            printf("Fuzzing all ies at the same time\n");
            break;
        }
        case 5:
        {
            printf("\e[33mDone with fuzzing PrbResp\e[39m\n");
            break;
        }
    }
}

//Updates PrbRespFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int PrbRespFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            PrbRespRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            PrbRespPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (PrbRespRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < PrbRespSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    PrbRespPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == PrbRespStates)
                {
                    PrbRespRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            PrbRespRunningState = 0;
            break;
        }
    }
    return 0;
}


//Creates Probe response frame
u_char *PrbRespFuzz(u_char *dstAddress, int *packetSize, u_char * radioTapHeader, u_char *myMAC)
{

    switch(fuzzState)
    {
        case 0:
        {
            return Prbieid(dstAddress, packetSize, radioTapHeader, myMAC, fuzzStep);
            break;
        }
        case 1:
        {
            return Prbflags(dstAddress, packetSize, radioTapHeader, myMAC, fuzzStep);
            break;
        }
        case 2:
        {
            return Prboversize(dstAddress, packetSize, radioTapHeader, myMAC, fuzzStep);
            break;
        }
        case 3:
        {
            return Prbduplicate(dstAddress, packetSize, radioTapHeader, myMAC, fuzzStep);
            break;
        }
        case 4:
        {
            return Prballies(dstAddress, packetSize, radioTapHeader, myMAC, fuzzStep);
            break;
        }
    }
    //return packet
    return NULL;    
}
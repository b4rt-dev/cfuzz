/*
Fuzzes Authentication Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "frameDefinitions.h"
#include "AUTHieid.h"
#include "AUTHoversize.h"
#include "AUTHduplicate.h"
#include "AUTHallies.h"
#include "AUTHstatic.h"

//Indecates whether the AuthFuzzer is running
int AuthRunningState = 0;

//Number of fuzzing states
const int AuthStates =  5;
//Steps of fuzzers for each fuzzing state
const int AuthSteps[] =   {256*4, 16, 16, 4, 14};

//Current state and step of the AuthFuzzer
int fuzzState;
int fuzzStep;

void AuthPrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing Auth Generic stuff\e[39m\n");
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
            printf("\e[33mDone with fuzzing Auth\e[39m\n");
            break;
        }
    }
}

//Updates AuthFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int AuthFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            AuthRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            AuthPrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (AuthRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < AuthSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    AuthPrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == AuthStates)
                {
                    AuthRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            AuthRunningState = 0;
            break;
        }
    }
    return 0;
}


//Creates Probe response frame
u_char *AuthFuzz(u_char *dstAddress, int *packetSize, u_char * radioTapHeader, u_char *myMAC)
{

    switch(fuzzState)
    {
        case 0:
        {
            return Authieid(dstAddress, packetSize, radioTapHeader, myMAC, fuzzStep);
            break;
        }
        case 1:
        {
            return Authoversize(dstAddress, packetSize, radioTapHeader, myMAC, fuzzStep);
            break;
        }
        case 2:
        {
            return Authduplicate(dstAddress, packetSize, radioTapHeader, myMAC, fuzzStep);
            break;
        }
        case 3:
        {
            return Authallies(dstAddress, packetSize, radioTapHeader, myMAC, fuzzStep);
            break;
        }
        case 4:
        {
            return Authstatic(dstAddress, packetSize, radioTapHeader, myMAC, fuzzStep);
            break;
        }
    }
    //return packet
    return NULL;    
}
/*
Fuzzes ht capabilities Information element
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the challengeFuzzer is running
int challengeRunningState = 0;

//Number of fuzzing states
const int challengeStates =  2;
//Steps of fuzzers for each fuzzing state
const int challengeSteps[] =   {45, 45};

//Current state and step of the challengeFuzzer
int fuzzState;
int fuzzStep;

void challengePrintCurrentState()
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("\e[33mFuzzing challenge text IE\e[39m\n");
            printf("Fuzzing challenge text incorrect length with data\n");
            break;
        }
        case 1: 
        {
            printf("Fuzzing challenge text incorrect length without data\n");
            break;
        }
        case 2:
        {
            printf("\e[33mDone with fuzzing challenge text\e[39m\n");
            break;
        }
    }
}

//Updates challengeFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int challengeFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            challengeRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            challengePrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (challengeRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < challengeSteps[fuzzState]-1)
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    challengePrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == challengeStates)
                {
                    challengeRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            challengeRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an challenge information element
infoElem challengeFuzz()
{
    infoElem challenge;

    //What to return when not fuzzed
    if (challengeRunningState == 0)
    {
        challenge.id = 0;
        challenge.len = 1;
        challenge.len_data = -1;
        challenge.data = "\xab";
    }
    else
    {
        switch (fuzzState) //update this
        {
            case 0: //challenge incorrect length with data
            {
                if (fuzzStep <= 38)
                {
                    challenge.id = 16;
                    challenge.len = fuzzStep;
                    challenge.len_data = 4;
                    challenge.data = "\x46\x55\x5a\x5a";
                }
                else
                {
                    challenge.id = 16;
                    challenge.len = 255 - (fuzzStep - 39);
                    challenge.len_data = 4;
                    challenge.data = "\x46\x55\x5a\x5a";
                }
                break;
            }
            case 1: //challenge incorrect length without data
            {
                if (fuzzStep <= 38)
                {
                    challenge.id = 16;
                    challenge.len = fuzzStep;
                    challenge.len_data = 0;
                    challenge.data = "";
                }
                else
                {
                    challenge.id = 16;
                    challenge.len = 255 - (fuzzStep - 39);
                    challenge.len_data = 0;
                    challenge.data = "";
                }
                break;
            }
        }
    }
    
    return challenge;
}
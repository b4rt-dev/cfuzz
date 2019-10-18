/*
Manages what to fuzz when.
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
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


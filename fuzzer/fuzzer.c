/*
Manages what to fuzz when.
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "frameDefinitions.h"
#include "fuzzSSID.h"
#include "fuzzRates.h"
#include "fuzzFH.h"
//CHANGE WHEN NEW SUBFUZZER

//CHANGE WHEN NEW SUBFUZZER
//Number of subfuzzers
#define SUBFUZZERS (3)

//CHANGE WHEN NEW SUBFUZZER
//Array of pointers to subfuzzers update functions
int (*p[SUBFUZZERS]) (int i) = {fhFuzzUpdate, ratesFuzzUpdate, ssidFuzzUpdate};

//State of sub-fuzzer
//-1 = Done
//0  = In progress
int subFuzzState = -1;

//Current sub-fuzzer
//Starts with -1 to prevent skipping the first sub-fuzzer
int subFuzzerIdx = -1;

//Flag to indicate if the done with all subfuzzers notification has been sent
int notifyDone = 0;

//Controls state of fuzzer, and therefore what to fuzz next
void increaseFuzzer()
{
    //while we still have sub-fuzzers to go
    if (subFuzzerIdx < SUBFUZZERS)
    {
        if (subFuzzState == -1)
        {
            subFuzzerIdx = subFuzzerIdx + 1;
            if (subFuzzerIdx < SUBFUZZERS)
            {
                subFuzzState = (*p[subFuzzerIdx]) (0);
            }
        }
        else
        {
            subFuzzState = (*p[subFuzzerIdx]) (1);
        }
    }
    //Done with all sub-fuzzers
    else
    {
        //Only do first time
        if (notifyDone == 0)
        {
            notifyDone = 1;
            printf("Done with all subfuzzers\n");
            //Optional exit
            exit(1);
        }
    }
}

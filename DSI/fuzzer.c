/*
Manages what to fuzz when.
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "frameDefinitions.h"
#include "fuzzERP.h"
//CHANGE WHEN NEW SUBFUZZER

//CHANGE WHEN NEW SUBFUZZER
//Number of subfuzzers
#define SUBFUZZERS (1)

//CHANGE WHEN NEW SUBFUZZER
//Array of pointers to subfuzzers update functions
//int (*p[SUBFUZZERS]) (int i) = {vendorFuzzUpdate, rsnFuzzUpdate, bssloadFuzzUpdate, extcapabFuzzUpdate, apreportFuzzUpdate, htinfoFuzzUpdate, htcapabFuzzUpdate, extratesFuzzUpdate, erpFuzzUpdate, requestFuzzUpdate, hoptableFuzzUpdate, hopparmFuzzUpdate, countryFuzzUpdate, ibssFuzzUpdate, cfFuzzUpdate, timFuzzUpdate, dsFuzzUpdate, fhFuzzUpdate, ratesFuzzUpdate, ssidFuzzUpdate};
int (*p[SUBFUZZERS]) (int i) = {erpFuzzUpdate};
//State of sub-fuzzer
//-1 = Done
//0  = In progress
int subFuzzState = -1;

//Current sub-fuzzer
//Starts with -1 to prevent skipping the first sub-fuzzer
int subFuzzerIdx = -1;

//Flag to indicate if the done with all subfuzzers notification has been sent
int notifyDone = 0;

int frameCounter = 0;

//Controls state of fuzzer, and therefore what to fuzz next
void increaseFuzzer()
{
    erpFuzzUpdate(0);
}

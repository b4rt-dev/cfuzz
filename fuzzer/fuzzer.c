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
#include "fuzzDS.h"
#include "fuzzCF.h"
#include "fuzzTIM.h"
#include "fuzzIBSS.h"
#include "fuzzCOUNTRY.h"
#include "fuzzHOPPARM.h"
#include "fuzzHOPTABLE.h"
#include "fuzzREQUEST.h"
#include "fuzzERP.h"
#include "fuzzEXTRATES.h"
#include "fuzzHTCAPAB.h"
#include "fuzzHTINFO.h"
#include "fuzzAPREPORT.h"
#include "fuzzEXTCAPAB.h"
#include "fuzzBSSLOAD.h"
#include "fuzzRSN.h"
#include "fuzzVENDOR.h"
#include "fuzzProbeResponse.h"
//CHANGE WHEN NEW SUBFUZZER

//CHANGE WHEN NEW SUBFUZZER
//Number of subfuzzers
#define SUBFUZZERS (20)

//CHANGE WHEN NEW SUBFUZZER
//Array of pointers to subfuzzers update functions
/*int (*p[SUBFUZZERS]) (int i) = {vendorFuzzUpdate, rsnFuzzUpdate, bssloadFuzzUpdate, 
extcapabFuzzUpdate, apreportFuzzUpdate, htinfoFuzzUpdate, htcapabFuzzUpdate, extratesFuzzUpdate, 
erpFuzzUpdate, requestFuzzUpdate, hoptableFuzzUpdate, hopparmFuzzUpdate, countryFuzzUpdate, 
ibssFuzzUpdate, cfFuzzUpdate, timFuzzUpdate, dsFuzzUpdate, fhFuzzUpdate, ratesFuzzUpdate, 
ssidFuzzUpdate}; */
int (*p[SUBFUZZERS]) (int i) = {
    ssidFuzzUpdate, ratesFuzzUpdate, fhFuzzUpdate, dsFuzzUpdate, cfFuzzUpdate, timFuzzUpdate, 
    ibssFuzzUpdate, countryFuzzUpdate, hopparmFuzzUpdate, hoptableFuzzUpdate, requestFuzzUpdate, 
    erpFuzzUpdate, extratesFuzzUpdate, htcapabFuzzUpdate, htinfoFuzzUpdate, apreportFuzzUpdate, 
    extcapabFuzzUpdate, bssloadFuzzUpdate, rsnFuzzUpdate, vendorFuzzUpdate};

//State of sub-fuzzer
//-1 = Done
//0  = In progress
int subFuzzState = -1;

//State of generic fuzzer
//-1 = Done
//0  = In progress
int genFuzzState = -1;

//Current sub-fuzzer
//Starts with -1 to prevent skipping the first sub-fuzzer
int subFuzzerIdx = -1;
//int subFuzzerIdx = 99; //to test generic fuzzing part

//Flag to indicate if the done with all subfuzzers notification has been sent
int notifyDone = 0;

int getNotifyDone()
{
    return notifyDone;
}

//Number of different sent frames (-1 because we start with increaseFuzzer)
int frameCounter = -1;

//Controls state of fuzzer, and therefore what to fuzz next
void increaseFuzzer()
{
    frameCounter = frameCounter + 1;
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
            printf("Sent %d different frames in total\n", frameCounter);

            printf("Moving on to generic fuzzing\n");
            genFuzzState = PrbRespFuzzUpdate(0);

        }
        else
        {
            if (genFuzzState != -1)
            {
                genFuzzState = PrbRespFuzzUpdate(1);
                if (genFuzzState == -1)
                {
                    printf("Done with generic fuzzing\n");
                    printf("Done with all probe response fuzzing\n");
                    printf("Fuzzer will now exit\n");
                    exit(0);
                }

            }
            else
            {
                printf("Fuzzer is done, but code should not get here\n");
                printf("Fuzzer will now exit\n");
                exit(0);
            }
        }
    }
}

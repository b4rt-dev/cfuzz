/*
Sub-fuzzer template for fuzzing a specific information element.
Change all places with "update this" as comment.
Also change all words with template in them.
And do not forget to change the header file.
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../frameDefinitions.h"

//Indecates whether the templateFuzzer is running
int templateRunningState = 0;

//Number of fuzzing states
const int templateStates =  2;          //update this
//Steps of fuzzers for each fuzzing state
const int templateSteps[] =   {2, 3};   //update this

//Current state and step of the templateFuzzer
int fuzzState;
int fuzzStep;

void templatePrintCurrentState() //update this
{
    switch (fuzzState)
    {
        case 0: 
        {
            printf("Fuzzing template state 1\n");
            break;
        }
        case 1: 
        {
            printf("Fuzzing template state 2\n");
            break;
        }
        case 2:
        {
            printf("Done with fuzzing template\n");
            break;
        }
    }
}

//Updates templateFuzzer
//Status 0 indicates start
//Status 1 indicates increaseStep
//Status 2 indicates stop
//Returns -1 if done with fuzzing
int templateFuzzUpdate(int status)
{
    switch (status)
    {
        case 0: //start fuzzer
        {
            templateRunningState    = 1;
            fuzzState       = 0;
            fuzzStep        = 0;
            templatePrintCurrentState();
            break;
        }
        case 1: //update fuzzer
        {
            if (templateRunningState == 1) //sanity check
            {
                //increase steps until all steps are done
                if (fuzzStep < templateSteps[fuzzState])
                    fuzzStep = fuzzStep + 1;
                //then increase state and notify
                else
                {
                    fuzzStep = 0;
                    fuzzState = fuzzState + 1;
                    templatePrintCurrentState();
                }
                //when all states are done, stop
                if (fuzzState == templateStates)
                {
                    templateRunningState = 0;
                    return -1;
                }
            }
            break;
        }
        case 2: //stop fuzzer
        {
            templateRunningState = 0;
            break;
        }
    }
    return 0;
}

//Returns an template information element
infoElem templateFuzz()
{
    infoElem template;

    //What to return when not fuzzed
    if (templateRunningState == 0) //update this
    {
        template.id = 0;
        template.len = 1;
        template.len_data = 1;
        template.data = "\xab";
    }
    else
    {
        switch (fuzzState) //update this
        {
            case 0: //template incorrect length
            {
                template.id = 0;
                template.len = fuzzStep;
                template.len_data = 3;
                template.data = "\xab\xcd\xef";
                break;
            }
            case 2:  //template null data
            {
                template.id = 0;
                template.len = 1;
                template.len_data = 1;
                template.data = "\x00";
                break;
            } 
        }
    }
    
    return template;
}
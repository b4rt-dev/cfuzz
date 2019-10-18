/*
Manages what to fuzz when.

TODO
- free after malloc
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../fuzzer.h"
#include "../frameDefinitions.h"

//Returns an SSID information element
infoElem ssidFuzz()
{
    infoElem ssid = {
            0,         //id
            4,         //len
            4,         //real length of data
            "\x46\x55\x5a\x5a" //data
            };

    switch (getFuzzState())
    {
        case 0: //SSID incorrect length with data
        {
            if (getFuzzStep() <= 38)
            {
                ssid.id = 0;
                ssid.len = getFuzzStep();
                ssid.len_data = 4;
                ssid.data = "\x46\x55\x5a\x5a";
            }
            else
            {
                ssid.id = 0;
                ssid.len = 255 - (getFuzzStep() - 39);
                ssid.len_data = 4;
                ssid.data = "\x46\x55\x5a\x5a";
            }
            break;
        }
        case 1: //SSID incorrect length without data
        {
            if (getFuzzStep() <= 38)
            {
                ssid.id = 0;
                ssid.len = getFuzzStep();
                ssid.len_data = 0;
                ssid.data = "";
            }
            else
            {
                ssid.id = 0;
                ssid.len = 255 - (getFuzzStep() - 39);
                ssid.len_data = 0;
                ssid.data = "";
            }
            break;
        }
        case 2: //SSID oversized length
        {
            if (getFuzzStep() < 8)
            {
                int dataSize = 33 + getFuzzStep();

                ssid.id = 0;
                ssid.len = dataSize;
                ssid.len_data = dataSize;
                //create data of datasize times 0x61
                u_char *data = malloc(dataSize);
                memset(data, 0x61, dataSize);
                ssid.data = data;
            }
            else
            {
                int dataSize = 255 - getFuzzStep();

                ssid.id = 0;
                ssid.len = dataSize;
                ssid.len_data = dataSize;
                //create data of datasize times 0x61
                u_char *data = malloc(dataSize);
                memset(data, 0x61, dataSize);
                ssid.data = data;
            }
            break;
        }
        case 3:  //SSID characters
        {
            ssid.id = 0;
            ssid.len = 32;
            ssid.len_data = 32;
            //create characters
            u_char *data = malloc(32);
            for (int i = 0; i < 32; i++)
            {
                data[i] = getFuzzStep();
            }
            ssid.data = data;
            break;
        } 
    }

    return ssid;
}
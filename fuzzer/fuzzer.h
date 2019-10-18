#ifndef FUZZER_H_
#define FUZZER_H_

#include "frameDefinitions.h"

infoElem ssidFuzz();

void increaseFuzzer();

int getFuzzState();

int getFuzzStep();

#endif
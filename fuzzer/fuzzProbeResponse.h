#ifndef FUZZPROBERESPONSE_H_
#define FUZZPROBERESPONSE_H_

int PrbRespFuzzUpdate(int status);

u_char *PrbRespFuzz(u_char *dstAddress, int *packetSize, u_char * radioTapHeader, u_char *myMAC);

#endif
#ifndef FUZZASSRESPONSE_H_
#define FUZZASSRESPONSE_H_

int AssRespFuzzUpdate(int status);

u_char *AssRespFuzz(u_char *dstAddress, int *packetSize, u_char * radioTapHeader, u_char *myMAC);

#endif
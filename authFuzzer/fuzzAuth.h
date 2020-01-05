#ifndef FUZZAUTH_H_
#define FUZZAUTH_H_

int AuthFuzzUpdate(int status);

u_char *AuthFuzz(u_char *dstAddress, int *packetSize, u_char * radioTapHeader, u_char *myMAC);

#endif
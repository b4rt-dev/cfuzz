#ifndef FRAMECREATOR_H_
#define FRAMECREATOR_H_

//Creates Probe response frame
u_char *createProbeResponse(u_char *dstAddress, int *packetSize, u_char * radioTapHeader, u_char *myMAC);


#endif
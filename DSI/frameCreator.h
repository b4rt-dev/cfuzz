#ifndef FRAMECREATOR_H_
#define FRAMECREATOR_H_

//Creates Authentication frame
u_char *createAuthResponse(u_char *dstAddress, int *packetSize, u_char * radioTapHeader, u_char *myMAC);

//Creates Association response
u_char *createAssResponse(u_char *dstAddress, int *packetSize, u_char * radioTapHeader, u_char *myMAC);

//Creates Probe response frame
u_char *createProbeResponse(u_char *dstAddress, int *packetSize, u_char * radioTapHeader, u_char *myMAC);


#endif
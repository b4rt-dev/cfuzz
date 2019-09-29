#ifndef CFUZZ_H_
#define CFUZZ_H_

//Information element
typedef struct {
	u_char id;
	u_char len;
	u_char *data;
} infoElem;


//Probe response frame
typedef struct {
    int len_radioTapHdr; 	//usually 32 bytes
    u_char *radioTapHdr;

    int len_type;			//1 byte
    u_char *type; 			//Protocol version, type and subtype

    int len_flags;			//1 byte
    u_char *flags;			//to DS, from DS, more Frag, Retry, Pwr Mgt, more Data, WEP, Order

    int len_duration;		//2 bytes
    u_char *duration;

    int len_destAddr;		//6 bytes
    u_char *destAddr;

    int len_sourceAddr;		//6 bytes
    u_char *sourceAddr;

    int len_bssAddr;		//6 bytes
    u_char *bssAddr;

    int len_seqNr;			//2 bytes 
    u_char *seqNr;

    int len_timeStamp; 		//8 bytes 
    u_char *timeStamp;

    int len_beaconInterval;	//2 bytes 
    u_char *beaconInterval;

    int len_capabInfo;		//2 bytes 
    u_char *capabInfo;

    int len_taggedParams; 	//variable size
    infoElem *taggedParams; 

    int len_fsc;			//4 bytes 
    u_char *fsc;

} probeResponse;

//Authentication response frame
typedef struct {
    int len_radioTapHdr; 	//usually 32 bytes
    u_char *radioTapHdr;

    int len_type;			//1 byte
    u_char *type; 			//Protocol version, type and subtype

    int len_flags;			//1 byte
    u_char *flags;			//to DS, from DS, more Frag, Retry, Pwr Mgt, more Data, WEP, Order

    int len_duration;		//2 bytes
    u_char *duration;

    int len_destAddr;		//6 bytes
    u_char *destAddr;

    int len_sourceAddr;		//6 bytes
    u_char *sourceAddr;

    int len_bssAddr;		//6 bytes
    u_char *bssAddr;

    int len_seqNr;			//2 bytes 
    u_char *seqNr;

    int len_authAlg; 		//2 bytes 
    u_char *authAlg;

    int len_authSeq;		//2 bytes 
    u_char *authSeq;

    int len_status;			//2 bytes 
    u_char *status;

    int len_fsc;			//4 bytes 
    u_char *fsc;

} authResponse;


//Association response frame
typedef struct {
    int len_radioTapHdr; 	//usually 32 bytes
    u_char *radioTapHdr;

    int len_type;			//1 byte
    u_char *type; 			//Protocol version, type and subtype

    int len_flags;			//1 byte
    u_char *flags;			//to DS, from DS, more Frag, Retry, Pwr Mgt, more Data, WEP, Order

    int len_duration;		//2 bytes
    u_char *duration;

    int len_destAddr;		//6 bytes
    u_char *destAddr;

    int len_sourceAddr;		//6 bytes
    u_char *sourceAddr;

    int len_bssAddr;		//6 bytes
    u_char *bssAddr;

    int len_seqNr;			//2 bytes 
    u_char *seqNr;

    int len_capabInfo; 		//2 bytes 
    u_char *capabInfo;

    int len_status;			//2 bytes 
    u_char *status;

    int len_assId;			//2 bytes 
    u_char *assId;

    int len_taggedParams; 	//variable size
    infoElem *taggedParams; 

    int len_fsc;			//4 bytes 
    u_char *fsc;

} assResponse;








#endif
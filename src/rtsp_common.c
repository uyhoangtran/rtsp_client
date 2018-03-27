#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "rtsp_common.h"
#include "md5.h"
static CmdTbl gcmdtbl[]={{"OPTIONS", 0},
                        {"DESCRIBE", 2},
                        {"SETUP", 4},
                        {"PLAY", 8},
                        {"PAUSE", 16},
                        {"GET_PARAMETER", 32},
                        {"SET_PARAMETER", 64},
                        {"REDIRECT", 128},
                        {"TEARDOWN", 256},
                        {"", -1}};

static uint32_t GetCmdTblKey(char *cmd)
{
    int32_t size = sizeof(gcmdtbl)/sizeof(CmdTbl);
    uint32_t i = 0x00;

    for (; i < size; i++){
        if (strncmp(gcmdtbl[i].cmd, cmd, strlen(gcmdtbl[i].cmd)) == 0){
            return gcmdtbl[i].key;
        }
    }
    return 0x00;
}

int32_t RtspCommandIsSupported(int32_t key, RtspSession *sess)
{
#ifdef RTSP_DEBUG
    printf("cmd stats : %d, key : %d\n", sess->cmdstats, key);
#endif
    if ((0x01 == (sess->cmdstats&0x01)) || (0x01 == (key&0x01)))
        return False;

    if ((key & sess->cmdstats) > 0x01)
        return True;
    return False;
}

void ParseOptionsPublic(char *buf, uint32_t size, RtspSession *sess)
{
    char *p = strstr(buf, OPTIONS_PUBLIC);
    if (NULL == p) {
        printf("SETUP: %s not found\n", SETUP_CPORT);
        return;
    }
    p += strlen(OPTIONS_PUBLIC);
    char *ptr = p;
    char tmp[32] = {0x00};
    do{
        memset(tmp, 0x00, sizeof(tmp));
        if (*ptr == ','){
            strncpy(tmp, p, ptr-p);
            tmp[ptr-p]='\0';
            p = ptr+1;
            sess->cmdstats += GetCmdTblKey(tmp);
        }else if (*ptr == '\r'){
            strncpy(tmp, p, ptr-p);
            tmp[ptr-p]='\0';
            break;
        }
        ptr++;
    }while(1);
    sess->cmdstats += GetCmdTblKey(tmp);
#ifdef RTSP_DEBUG
    printf("cmd stats : %d\n", sess->cmdstats);
#endif
    return;
}


static void GetClientPort(char *buf, uint32_t size, RtspSession *sess)
{
    char *p = strstr(buf, SETUP_CPORT);
    if (!p) {
        printf("SETUP: %s not found\n", SETUP_CPORT);
        return;
    }
    p += strlen(SETUP_CPORT);

    char *ptr = p;
    do{
        if (*ptr == '-'){
            break;
        }
        ptr++;
    }while(1);

    char tmp[8] = {0x00};
    strncpy(tmp, p, ptr-p);
    sess->transport.udp.cport_from = atol(tmp);
    memset(tmp, 0x00, sizeof(tmp));
    ptr++;

    p = ptr;
    do{
        if (*ptr == ';' || *ptr == '\r'){
            break;
        }
        ptr++;
    }while(1);
    strncpy(tmp, p, ptr-p);
    sess->transport.udp.cport_to = atol(tmp);
    memset(tmp, 0x00, sizeof(tmp));

    return;
}

static void GetServerPort(char *buf, uint32_t size, RtspSession *sess)
{
    char tmp[8] = {0x00};
    memset(tmp, 0x00, sizeof(tmp));
    char *p = strstr(buf, SETUP_SPORT);
    if (!p) {
        printf("SETUP: %s not found\n", SETUP_SPORT);
        return;
    }
    p += strlen(SETUP_SPORT);
    char *ptr = p;
    do{
        if (*ptr == '-'){
            break;
        }
        ptr++;
    }while(1);
    strncpy(tmp, p, ptr-p);
    sess->transport.udp.sport_from = atol(tmp);
    memset(tmp, 0x00, sizeof(tmp));
    ptr++;

    p=ptr;
    do{
        if (*ptr == ';' || *ptr == '\r'){
            break;
        }
        ptr++;
    }while(1);
    strncpy(tmp, p, ptr-p);
    sess->transport.udp.sport_to = atol(tmp);

    return;
}

int32_t ParseUdpPort(char *buf, uint32_t size, RtspSession *sess)
{
    GetClientPort(buf, size, sess);
    GetServerPort(buf, size, sess);

#ifdef RTSP_DEBUG
    printf("client port from %d to %d\n", \
            sess->transport.udp.cport_from, \
            sess->transport.udp.cport_to);
    printf("server port from %d to %d\n", \
            sess->transport.udp.sport_from, \
            sess->transport.udp.sport_to);
#endif
    return True;
}

int32_t ParseTimeout(char *buf, uint32_t size, RtspSession *sess)
{
    char *p = strstr(buf, TIME_OUT);
    if (!p) {
        printf("GET_PARAMETER: %s not found\n", TIME_OUT);
        return False;
    }
    p += strlen(TIME_OUT);
    char *ptr = p;
    do{
        if (*ptr == ';' || *ptr == '\r'){
            break;
        }
        ptr++;
    }while(1);

    char tmp[8] = {0x00};
    strncpy(tmp, p, ptr-p);
    sess->timeout = atol(tmp);
#ifdef RTSP_DEBUG
    printf("timeout : %d\n", sess->timeout);
#endif
    return True;
}

int32_t ParseSessionID(char *buf, uint32_t size, RtspSession *sess)
{
    /* Session ID */
    char *ptr = strstr(buf, SETUP_SESSION);
    if (!ptr) {
        printf("SETUP: %s not found\n", SETUP_SESSION);
        return False;
    }
    ptr += strlen(SETUP_SESSION);
    char *p = ptr;
    do{
        if (*p == ';' || *p == '\r'){
            break;
        }
        p++;
    }while(1);

    memset(sess->sessid, '\0', sizeof(sess->sessid));
    memcpy((void *)sess->sessid, (const void *)ptr, p-ptr);
#ifdef RTSP_DEBUG
    printf("sessid : %s\n", sess->sessid);
#endif
    return True;
}


int32_t ParseInterleaved(char *buf, uint32_t num, RtspSession *sess)
{
    char *p = strstr(buf, TCP_INTERLEAVED);
    if (!p) {
        printf("SETUP: %s not found\n", TCP_INTERLEAVED);
        return False;
    }

    p += strlen(TCP_INTERLEAVED);
    char *ptr = p;
    do{
        if (*ptr == '-'){
            break;
        }
        ptr++;
    }while(1);

    char tmp[8] = {0x00};
    strncpy(tmp, p, ptr-p);
    sess->transport.tcp.start = atol(tmp);
    memset(tmp, 0x00, sizeof(tmp));
    ptr++;

    p = ptr;
    do{
        if (*ptr == ';' || *ptr == '\r'){
            break;
        }
        ptr++;
    }while(1);
    strncpy(tmp, p, ptr-p);
    sess->transport.udp.cport_to = atol(tmp);
    memset(tmp, 0x00, sizeof(tmp));

#ifdef RTSP_DEBUG
    printf("tcp interleaved from %d to %d\n", \
            sess->transport.tcp.start, \
            sess->transport.tcp.end);
#endif
    return True;
}


void RtspIncreaseCseq(RtspSession *sess)
{
    sess->cseq++;
    return;
}

void GetSdpVideoAcontrol(char *buf, uint32_t size, RtspSession *sess)
{
    char *ptr = (char *)memmem((const void*)buf, size,
            (const void*)SDP_M_VIDEO, strlen(SDP_M_VIDEO)-1);
    if (NULL == ptr){
        fprintf(stderr, "Error: m=video not found!\n");
        return;
    }

    ptr = (char *)memmem((const void*)ptr, size,
            (const void*)SDP_A_CONTROL, strlen(SDP_A_CONTROL)-1);
    if (NULL == ptr){
        fprintf(stderr, "Error: a=control not found!\n");
        return;
    }

    char *endptr = (char *)memmem((const void*)ptr, size,
            (const void*)"\r\n", strlen("\r\n")-1);
    if (NULL == endptr){
        fprintf(stderr, "Error: %s not found!\n", "\r\n");
        return;
    }
    ptr += strlen(SDP_A_CONTROL);
    if ('*' == *ptr){
        /* a=control:* */
        printf("a=control:*\n");
        return;
    }else{
        /* a=control:rtsp://ip:port/track1  or a=control : TrackID=1*/
        memcpy((void *)sess->vmedia.control, (const void*)(ptr), (endptr-ptr));
        sess->vmedia.control[endptr-ptr] = '\0';
    }

    return;
}

void GetSdpVideoTransport(char *buf, uint32_t size, RtspSession *sess)
{
    char *ptr = (char *)memmem((const void*)buf, size,
            (const void*)SDP_M_VIDEO, strlen(SDP_M_VIDEO)-1);
    if (NULL == ptr){
        fprintf(stderr, "Error: m=video not found!\n");
        return;
    }

    ptr = (char *)memmem((const void*)ptr, size,
            (const void*)UDP_TRANSPORT, strlen(UDP_TRANSPORT)-1);
    if (NULL != ptr){
        sess->trans = RTP_AVP_UDP;
    }else{
        ptr = (char *)memmem((const void*)ptr, size,
                (const void*)TCP_TRANSPORT, strlen(TCP_TRANSPORT)-1);
        if (NULL != ptr)
            sess->trans = RTP_AVP_TCP;
    }

    return;
}

int32_t ParseSdpProto(char *buf, uint32_t size, RtspSession *sess)
{
    GetSdpVideoTransport(buf, size, sess);
    GetSdpVideoAcontrol(buf, size, sess);
#ifdef RTSP_DEBUG
    printf("video control: %s\n", sess->vmedia.control);
#endif
    return True;
}

/*********************************************************************/
/*************************     HOANG      ****************************/
/*********************************************************************/

int32_t ParseUnauthorizedMess(char *buf, uint32_t size, RtspSession *sess)
{
    /* Parsing REALM */
    char *p = strstr(buf,AUTH_REALM);
    if (NULL == p) {
        printf("%s not found\n",AUTH_REALM);
        return False;
    }
    p += strlen(AUTH_REALM);
    char *ptr = p+1;
    char *tmp = calloc(sizeof(char),32);
    char i=0;
    while(1){
        if(*ptr != '"')
        {
            *(tmp + i) = *ptr;
            i++;
            ptr++;
        }
        else
        {
            break;
        }
    }
    memset(sess->auth_struct.realm,0x00,33);
    memcpy(sess->auth_struct.realm,tmp,32);
    
    /* Parsing NONCE */
    p = strstr(buf,AUTH_NONCE);
    if (NULL == p) {
        printf("%s not found\n",AUTH_NONCE);
        return False;
    }
    p += strlen(AUTH_NONCE);
    memset(sess->auth_struct.nonce,0x00,33);
    memcpy(sess->auth_struct.nonce,p+1,32);
    free(tmp);

#ifdef RTSP_DEBUG
    printf("realm : %s\n", sess->auth_struct.realm);
    printf("nonce: %s\n",sess->auth_struct.nonce);
#endif
    return True;
}

void MakeDigestCodeResponse(RtspSession *sess,const char* command)
{
    uint16_t ha1_length,ha2_length,response_length;
    ha1_length = strlen(sess->username)+strlen(sess->auth_struct.realm)+strlen(sess->password) + 2;
    ha2_length = strlen(command)+strlen(sess->url) + 1;
    response_length = 32*3 + 2;

    char *ha1_str,*ha2_str,*response_str;
    char *ha1 = (char *)calloc(sizeof(char),33);
    char *ha2 = (char *)calloc(sizeof(char),33);
    /* Calculate ha1 */
    if((ha1_str = (char *)malloc(ha1_length)) == NULL)
    {
        #ifdef RTSP_DEBUG
            fprintf(stderr,"Failed to make Digest Response: malloc error\n");
        #endif
        return;
    }
    sprintf(ha1_str,"%s:%s:%s",sess->username,sess->auth_struct.realm,sess->password);
    md5(ha1_str,ha1_length,ha1);
    //memcpy(sess->auth_struct.ha1,ha1_str,sizeof(sess->auth_struct.ha1));
    puts(ha1_str);
    free(ha1_str);
    /* Calculate ha2 */
    if((ha2_str = (char *)malloc(ha2_length)) == NULL)
    {
        #ifdef RTSP_DEBUG
            fprintf(stderr,"Failed to make Digest Response: malloc error\n");
        #endif
        return;
    }
    sprintf(ha2_str,"%s:%s",command,sess->url);
    md5(ha2_str,ha2_length,ha2);
   // memcpy(sess->auth_struct.ha2,ha2_str,sizeof(sess->auth_struct.ha2));
    puts(ha2_str);
    puts(ha2);
    free(ha2_str);

    /* Calculate response */
    if((response_str = (char *)malloc(response_length)) == NULL)
    {
        #ifdef RTSP_DEBUG
            fprintf(stderr,"Failed to make Digest Response: malloc error\n");
        #endif
        return;
    }
    sprintf(response_str,"%s:%s:%s",ha1,sess->auth_struct.nonce,ha2);
    md5(response_str,response_length,sess->auth_struct.auth_response);
    free(ha1);
    free(ha2);
    printf("\n%s",response_str);
    printf("\nresponse_length %d\n",response_length);
    free(response_str);
}
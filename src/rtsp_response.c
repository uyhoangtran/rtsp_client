#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rtsp.h"
#include "rtsp_response.h"
#include "net.h"


static char* GetSeperator(BufferControl *bctrl)
{
	char *sep = strstr(bctrl->buffer, SEPERATOR);
	if (NULL != sep)
	{
		bctrl->offset = sep - bctrl->buffer;
		bctrl->offset += strlen(SEPERATOR);
		return sep;
	}

	return NULL;
}

static uint32_t GetContentLength(char *buf, uint32_t size)
{
    char *p = strstr(buf, CONTENT_LENGTH);
    if (NULL == p) {
        p = strstr(buf, CONTENT_length);
        if (NULL == p){
            fprintf(stderr, "Error:Connect-length not found\n");
            return 0x00;
        }
    }

    p += strlen(CONTENT_LENGTH);
    char *ptr = p;
    do{
        if (*ptr == '\r' || *ptr == ';')
            break;
        ptr++;
    }while(1);

    char tmp[8] = {0x00};
    strncpy(tmp, p, ptr-p);
    return  atol(tmp);
}

int32_t RtspReceiveResponse(uint32_t sockfd, BufferControl *bctrl)
{
    char *buf = bctrl->buffer;
    uint32_t size = sizeof(bctrl->buffer);
    int32_t num = TcpReceiveData(sockfd, buf, size-1);
    if (num <= 0) {
        printf("Error: Server did not respond properly, closing...");
        return False;
    }

    bctrl->len = num;
    GetSeperator(bctrl);
    uint32_t contentlen = GetContentLength(buf, num);
    if ((contentlen == 0x00 ) || ((num-bctrl->offset)==contentlen)){
        return num;
    }
    num = TcpReceiveData(sockfd, buf+bctrl->len, contentlen-(num-bctrl->offset));
    if (num <= 0) {
        printf("Error: Server did not respond properly, closing...");
        return False;
    }

    bctrl->len += num;

	return bctrl->len;
}


status_code_t RtspCheckResponseStatus(char *buff)
{
    int32_t offset = strlen(RTSP_RESPONSE);
    char buf[8], *sep = NULL;
    status_code_t status_code = ST_ERROR;

    if (strncmp((const char*)buff, (const char*)RTSP_RESPONSE, offset) != 0) {
        return status_code;
    }

    sep = strchr((const char *)buff+offset, ' ');
    if (!sep) {
        return status_code;
    }

    memset(buf, '\0', sizeof(buf));
    strncpy((char *)buf, (const char *)(buff+offset), sep-buff-offset);

    status_code = atoi(buf);

    return status_code;
}




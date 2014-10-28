#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>

#include "rtspClient.h"

static void help(int status);
static void help(int status)
{
    printf("Usage: rpsp_client -u rtsp://url\n\n");
    printf("  -u, --url=rtsp://      rtsp address\n");
	printf("  -h, --help             print this help\n");
	printf("\n");
	exit(status);
}


int main(int argc, char **argv)
{
    int opt;
    char *url = NULL;
    static const struct option long_opts[] = {
                            { "url", required_argument, NULL, 'u'},
                            { "help", no_argument, NULL, 'h'},
                            { NULL, 0, NULL, 0 }
                        };

    while ((opt = getopt_long(argc, argv, "u:h",
                       long_opts, NULL)) != -1) {
        switch (opt) {
            case 'u':
                url  = strdup(optarg);
                break;
            case 'h':
                help(EXIT_SUCCESS);
                break;
            default:
                break;
        }
    }

    if (NULL == url){
        fprintf(stderr, "Error : Url Address Equal Null.\n");
        return 0x00;
    }

    RtspClientSession *sess = InitRtspClientSession();
    if (False == ParseUrl(url, sess)){
        fprintf(stderr, "Error : Invalid Url Address.\n");
        return 0x00;
    }

    /* RTSP Event Loop */
    while(1){
        RtspEventLoop(sess);
        printf("RTSP Event Loop stopped, waiting 5 seconds...\n");
        sleep(5);
        break;
    }

    DeleteRtspClientSession(sess);
    return 0x00;
}


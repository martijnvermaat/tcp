#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include "tcp.h"

#define LISTEN_PORT 80
#define TIME_OUT 5
#define MAX_REQUEST_LENGTH 512


/*
  httpd.c
  A simple HTTP/1.0 server.
*/


int serve(void);


static void alarm_handler(int sig) {
    /* just return to interrupt */
}


int main(void) {

    char *eth, *ip1, *ip2;

    eth = getenv("ETH");
    if (!eth) {
        fprintf(stderr, "The ETH environment variable must be set!\n");
        return 1;
    }

    ip1 = getenv("IP1");
    ip2 = getenv("IP2");
    if ((!ip1)||(!ip2)) {
        fprintf(stderr, "The IP1 and IP2 environment variables must be set!\n");
        return 1;
    }

    if (tcp_socket() != 0) {
        fprintf(stderr, "HTTPD: Opening socket failed\n");
        return 1;
    }

    while (serve()) { }

    printf("Listening failed.\n");

    return 1;

}


int serve(void) {

    char buffer[MAX_REQUEST_LENGTH];
    ipaddr_t saddr;

    if (tcp_listen(LISTEN_PORT, &saddr) < 0) {
        return 0;
    }

    signal(SIGALRM, alarm_handler);
    alarm(TIME_OUT);
    if (tcp_read(buffer, MAX_REQUEST_LENGTH) < 1) {
        return 1;
    }
    alarm(0);

    if (tcp_write("Here's my response.", 19) != 19) {
        return 1;
    }

    if (tcp_close() != 0) {
        return 0;
    }

    return 1;

}

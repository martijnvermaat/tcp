#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include "tcp.h"

#define SERVER_PORT 80
#define TIME_OUT 5
#define MAX_RESPONSE_LENGTH 1024


/*
  httpc.c
  A simple HTTP/1.0 client.
*/


int do_request(char *ip2);


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
        fprintf(stderr, "HTTPC: Opening socket failed\n");
        return 1;
    }

    return do_request(ip2);

}


int do_request(char *ip2) {

    char response_buffer[MAX_RESPONSE_LENGTH];

    if (tcp_connect(inet_aton(ip2), SERVER_PORT) != 0) {
        return 1;
    }

    if (tcp_write("Dit is mijn request.", 20) != 20) {
        return 1;
    }

    signal(SIGALRM, alarm_handler);
    alarm(TIME_OUT);
    if (tcp_read(response_buffer, MAX_RESPONSE_LENGTH) < 1) {
        return 1;
    }
    alarm(0);

    printf("*** Response: ***\n");
    printf(response_buffer);

    if (tcp_close() != 0) {
        return 1;
    }

    signal(SIGALRM, alarm_handler);
    alarm(TIME_OUT);
    while (tcp_read(response_buffer, MAX_RESPONSE_LENGTH) > 0) {}
    alarm(0);

    return 0;

}

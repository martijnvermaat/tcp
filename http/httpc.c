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
#define RBUFFER_SIZE 1024


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
        fprintf(stdout, "The ETH environment variable must be set!\n");
        return 1;
    }

    ip1 = getenv("IP1");
    ip2 = getenv("IP2");
    if ((!ip1)||(!ip2)) {
        fprintf(stdout, "The IP1 and IP2 environment variables must be set!\n");
        return 1;
    }

    if (tcp_socket() != 0) {
        fprintf(stdout, "HTTPC: Opening socket failed\n");
        return 1;
    }

    return do_request(ip2);

}


int do_request(char *ip2) {

    char response_buffer[RBUFFER_SIZE+1];
    int length;

    if (tcp_connect(inet_aton(ip2), SERVER_PORT) != 0) {
        return 1;
    }

    if (tcp_write("GET /index.html HTTP/1.0\r\n", 26) != 26) {
        return 1;
    }

    do {
        signal(SIGALRM, alarm_handler);
        alarm(TIME_OUT);
        length = tcp_read(response_buffer, RBUFFER_SIZE);
        if (length < 0) return 1;
        alarm(0);

        response_buffer[length] = '\0';
        fprintf(stderr, response_buffer);
    } while (length);

    printf("*** Response was cool ***");

    if (tcp_close() != 0) {
        return 1;
    }

    signal(SIGALRM, alarm_handler);
    alarm(TIME_OUT);
    while (tcp_read(response_buffer, RBUFFER_SIZE) > 0) {}
    alarm(0);

    return 0;

}

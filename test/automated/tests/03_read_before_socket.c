#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "tcp.h"


/*
  Test read_before_socket.c

  Tries to do a tcp_read before there is opened a socket.
*/


static void alarm_handler(int sig) {
    /* just return to interrupt */
}


int main(void) {

    char buf[8];
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

    signal(SIGALRM, alarm_handler);
    alarm(5);

    if (tcp_read(buf, 1) != -1) {
        fprintf(stderr, "Client: Reading should've failed\n");
        return 1;
    }

    alarm(0);

    return 0;

}

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "tcp.h"



/*
  Test write_before_socket.c

  Tries to do a tcp_write before there is opened a socket.
*/


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

    if (tcp_write(buf, 1) != -1) {
        fprintf(stderr, "Client: Writing should've failed\n");
        return 1;
    }

    return 0;

}

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include "tcp.h"


/*
  Test signal.c

  Can we set an alarm to stop a blocking listen?
  
*/

static void alarm_handler(int sig) {
    fprintf(stderr,"test 21: alarm went of\n");
    fflush(stderr);
    /* just return to interrupt */
}


int main(void) {

    char client_buf[1], server_buf[1];
    char *eth, *ip1, *ip2;

    unsigned char j, v;

    ipaddr_t saddr;

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

    /* Server process running in $IP2 */
    eth[0]='2';

    if (tcp_socket() != 0) {
        fprintf(stderr, "Server: Opening socket failed\n");
        return 1;
    }

    signal(SIGALRM, alarm_handler);
    alarm(5);
    
    if (tcp_listen(80, &saddr) < 0) {
        fprintf(stderr, "Server: Listening for client failed\n");
        return 1;
    }
    
    alarm(0);
    signal(SIGALRM, alarm_handler);
    alarm(5);

    if (tcp_read(server_buf, 1) < 0) {
        fprintf(stderr, "Server: Reading byte 1 failed\n");
        return 1;
    }
    fprintf(stderr,"server read one byte\n");
    fflush(stderr);
    alarm(0);
    signal(SIGALRM, alarm_handler);
    alarm(2);

    if (tcp_read(server_buf, 1) < 0) {
        fprintf(stderr, "Server: Reading byte 2 failed\n");
        return 1;
    }
    fprintf(stderr,"server passed blocking read\n");
    fflush(stderr);
    alarm(0);

    if (tcp_close() != 0) {
        fprintf(stderr, "Server: Closing connection failed (this is what we want)\n");
        return 1;
    }

    signal(SIGALRM, alarm_handler);
    alarm(5);

    while (tcp_read(server_buf, 4) > 0) {}

    alarm(0);
    
}

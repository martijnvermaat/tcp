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

  Can we set an alarm to stop a blocking read when te client abruptly
  aborts connection?
  
*/

static void alarm_handler(int sig) {
    fprintf(stderr,"alarm went of\n");
    fflush(stderr);
    /* just return to interrupt */
}


int main(void) {

    char client_buf[1], server_buf[1];
    char *eth, *ip1, *ip2;

    int pid, status;

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

    pid = fork();

    if (pid == -1) {
        fprintf(stderr, "Unable to fork client process\n");
        return 1;
    }

    if (pid == 0) {

        /* Client process running in $IP1 */
        eth[0] = '1';

        if (tcp_socket() != 0) {
            fprintf(stderr, "Client: Opening socket failed\n");
            return 1;
        }

        if (tcp_connect(inet_aton(ip2), 80) != 0) {
            fprintf(stderr, "Client: Connecting to server failed\n");
            return 1;
        }
        
        client_buf[0] = 255;
        if (tcp_write(client_buf, 1) != 1) {
            fprintf(stderr, "Client: Writing ASCII character failed\n");
            return 1;
        }
        fprintf(stderr,"Client: Sent one byte, will stop now\n");
        fflush(stderr);
        /* do nothing */        
        return 0;

    } else {

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


        /* Wait for client process to finish */
        while (wait(&status) != pid);
        return 0;
    }
    
}

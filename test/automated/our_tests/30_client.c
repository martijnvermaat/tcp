#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include "tcp.h"

#define BUF_SIZE 45000
/*
  Test big_test.c

  sends 80 kilobyte
*/


void print_bits(char c);
int alarm_went_of = 0;

static void alarm_handler(int sig) {
    fprintf(stderr, "test 24: alarm went of");
    fflush(stderr); 
    alarm_went_of = 1;
    /* just return to interrupt */
}


int main(void) {
    
    char server_buf[BUF_SIZE], client_buf[BUF_SIZE];
    char *eth, *ip1, *ip2;

    int pid, status, total, read;
    int j, v;

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
    
            /* fill buffer with ASCII pattern 012345670123... */
        for (v=0;v<BUF_SIZE;v++) {
            client_buf[v] = (v % 8) + 48;
        }

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
        
        j = tcp_write(client_buf, BUF_SIZE);
        if (j < 1) {
            fprintf(stderr, "Client: Writing failed\n"); 
            return 1;
        }
        fprintf(stderr,"Client: Sent %d Kbytes\n",j);    
       
        
        if (tcp_close() != 0) {
            fprintf(stderr, "Client: Closing connection failed\n");
            return 1;
        }

        signal(SIGALRM, alarm_handler);
        alarm(3);

        while (tcp_read(client_buf, 4) > 0) {}

        alarm(0);

        return 0;
    
}



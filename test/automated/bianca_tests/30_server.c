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
        
        total = 0;
        fprintf(stderr,"\n\n\n\n\n\n\nserver: starting to read...\n");
        fflush(stderr);
        while (total < BUF_SIZE && !alarm_went_of) {
            signal(SIGALRM, alarm_handler);
            alarm(5);

            read = tcp_read(&server_buf[total], BUF_SIZE - total);
            if (read < 0) {
                fprintf(stderr, "Server: Reading %d bytes failed\n",BUF_SIZE-total);
                return 1;
            } else {
                total += read;
                fprintf(stderr, "Server: Read %d bytes\n",read);
            }
            alarm(0);
        }
        fprintf(stderr, "Server: Read %d bytes in total. Closing connection...\n",total);
        
        if (tcp_close() != 0) {
            fprintf(stderr, "Server: Closing connection failed\n");
            return 1;
        }
    
        
        for (j=0; j<total; j++) {
            if (server_buf[j] != (j % 8)+48) {
                fprintf(stderr,"ERROR!! Server read error: expected: %d, read: %d\n",(j % 8)+48,server_buf[j]);
            }
        }
        fprintf(stderr, "Server: byte check done.\n",total);


        signal(SIGALRM, alarm_handler);
        alarm(5);

        while (tcp_read(server_buf, 4) > 0) {
            fprintf(stderr,"did one last read\n");
        }

        alarm(0);

        /* Wait for client process to finish */
        while (wait(&status) != pid);

        return 0;

    
    
}



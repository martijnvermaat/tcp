#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include "tcp.h"

#define BUF_SIZE 20000
/*
  Test big_test.c

  sends 50 kilobyte
*/

void print_bits(char c);

static void alarm_handler(int sig) {
    fprintf(stderr, "test 24: alarm went of");
    fflush(stderr); 
    /* just return to interrupt */
}


int main(void) {
    
    char client_buf[BUF_SIZE], server_buf[BUF_SIZE];
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
    
    /* fill buffer with pattern 012345670123... */
    for (v=0;v<BUF_SIZE;v++) {
        client_buf[v] = v % 8;
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
        total = 0;
        fprintf(stderr,"server: starting to read...\n");
        fflush(stderr);
        while (total < BUF_SIZE) {

            alarm(10);

            read = tcp_read(server_buf, BUF_SIZE - total);
            if (read < 0) {
                fprintf(stderr, "Server: Reading %d bytes failed\n",BUF_SIZE-total);
                return 1;
            } else {
                total += read;
                fprintf(stderr, "Server: Read %d bytes\n",read);
            }
            alarm(0);
        }
        fprintf(stderr, "Server: Read %d bytes in total...closing connection.\n",total);

        if (tcp_close() != 0) {
            fprintf(stderr, "Server: Closing connection failed\n");
            return 1;
        }

        signal(SIGALRM, alarm_handler);
        alarm(5);

        while (tcp_read(server_buf, 4) > 0) {}

        alarm(0);

        /* Wait for client process to finish */
        while (wait(&status) != pid);

        return 0;

    }
    
}


#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include "tcp.h"


/*
  Test all_ascii.c

  Tries to send an read all ascii characters one by one.
  So it basically does 256 writes and 256 reads of one byte, all
  with a different value.
*/

void print_bits(char c);

static void alarm_handler(int sig) {
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
        /*ip_init();*/

        if (tcp_socket() != 0) {
            fprintf(stderr, "Client: Opening socket failed\n");
            return 1;
        }

        if (tcp_connect(inet_aton(ip2), 80) != 0) {
            fprintf(stderr, "Client: Connecting to server failed\n");
            return 1;
        }
        
        for (v=0; v<255; v++) {
            client_buf[0] = v;
            if (tcp_write(client_buf, 1) != 1) {
                fprintf(stderr, "Client: Writing ASCII character %u failed (", v);
                print_bits(v);fprintf(stderr,")\n");   
                return 1;
            }
            printf("Client: Sent ASCII character %u (", v);
            print_bits(v);printf(")\n");
        }
        /* send last byte (255)*/
        client_buf[0] = v;
        if (tcp_write(client_buf, 1) != 1) {
            fprintf(stderr, "Client: Writing ASCII character %u failed (", v);
            print_bits(v);fprintf(stderr,")\n");   
            return 1;
        }
        printf("Client: Sent ASCII character %u (", v);
        print_bits(v);printf(")\n");

        
        
        if (tcp_close() != 0) {
            fprintf(stderr, "Client: Closing connection failed\n");
            return 1;
        }

        signal(SIGALRM, alarm_handler);
        alarm(5);

        while (tcp_read(server_buf, 4) > 0) {}

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

        for (j=0; j<255; j++) {

            signal(SIGALRM, alarm_handler);
            alarm(5);

            if (tcp_read(server_buf, 1) < 0) {
                fprintf(stderr, "Server: Reading 1 byte failed\n");
                return 1;
            }

            alarm(0);

            printf("Server: Found byte %u\n", (tcp_u8t) server_buf[0]);

            if (((tcp_u8t)server_buf[0]) != j) {
                fprintf(stderr, "Server: Reading ASCII character %u failed\n", j);
                fprintf(stderr, "Server: Found ASCII character %u\n", server_buf[0]);
                return 1;
            }

        }
        signal(SIGALRM, alarm_handler);
        alarm(5);

        if (tcp_read(server_buf, 1) < 0) {
            fprintf(stderr, "Server: Reading 1 byte failed\n");
            return 1;
        }

        alarm(0);

        fprintf(stderr, "Server: Found byte %u\n", (tcp_u8t) server_buf[0]);

        if (((tcp_u8t)server_buf[0]) != j) {
            fprintf(stderr, "Server: Reading ASCII character %u failed\n", j);
            fprintf(stderr, "Server: Found ASCII character %u\n", server_buf[0]);
            return 1;
        }






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


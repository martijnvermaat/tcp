#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "tcp.h"


/*
  Test all_ascii.c

  Tries to send an read all ascii characters one by one.
  So it basically does 256 writes and 256 reads of one byte, all
  with a different value.
*/


int main(void) {

    char client_buf[1], server_buf[1];
    char *eth, *ip1, *ip2;

    int pid, status;

    int i, j;

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

    alarm(15);

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

        for (i=-127; i<128; i++) {

            client_buf[0] = i;

            if (tcp_write(client_buf, 1) != 1) {
                fprintf(stderr, "Client: Writing ASCII character %d failed\n", i);
                return 1;
            }

        }

        if (tcp_close() != 0) {
            fprintf(stderr, "Client: Closing connection failed\n");
            return 1;
        }

        while (tcp_read(server_buf, 4) > 0) {}

        return 0;

    } else {

        /* Server process running in $IP2 */

        eth[0]='2';
        /*ip_init();*/

        if (tcp_socket() != 0) {
            fprintf(stderr, "Server: Opening socket failed\n");
            return 1;
        }

        if (tcp_listen(80, &saddr) < 0) {
            fprintf(stderr, "Server: Listening for client failed\n");
            return 1;
        }

        for (j=-127; j<128; j++) {

            if (tcp_read(server_buf, 1) < 0) {
                fprintf(stderr, "Server: Reading 1 byte failed\n");
                return 1;
            }

            if (server_buf[0] != j) {
                fprintf(stderr, "Server: Reading ASCII character %d failed\n", j);
                fprintf(stderr, "Server: Found ASCII character %d\n", server_buf[0]);
                return 1;
            }

        }

        if (tcp_close() != 0) {
            fprintf(stderr, "Server: Closing connection failed\n");
            return 1;
        }

        while (tcp_read(server_buf, 4) > 0) {}

        /* Wait for client process to finish */
        while (wait(&status) != pid);

        return 0;

    }


}

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "tcp.h"


/*
  Test basic.c

  Standard listen and connect. Read and write to both sides,
  with compares on received data and expected data. Close.
*/


int main(void) {

    char client_buf[8], server_buf[8];
    char *eth, *ip1, *ip2;

    int pid, status;

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

    /* shouldn't alarm() be called INSIDE the two different processes below? */
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

        if (tcp_write("foo", 4) != 4) {
            fprintf(stderr, "Client: Writing 'foo' failed\n");
            return 1;
        }

        if (tcp_read(client_buf, 4) != 4) {
            fprintf(stderr, "Client: Reading 4 bytes failed\n");
            return 1;
        }

        if (strcmp(client_buf, "bar")) {
            fprintf(stderr, "Client: Reading 'bar' failed\n");
            return 1;
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

        if (tcp_read(server_buf, 4) != 4) {
            fprintf(stderr, "Server: Reading 4 bytes failed\n");
            return 1;
        }

        if (strcmp(server_buf, "foo")) {
            fprintf(stderr, "Server: Reading 'foo' failed\n");
            return 1;
        }

        if (tcp_write("bar", 4) != 4) {
            fprintf(stderr, "Server: Writing 'bar' failed\n");
            return 1;
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

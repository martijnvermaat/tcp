#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include "tcp.h"

/*
  Decide if we use 'size' or
  'length' (for ALL code).
*/
#define LISTEN_PORT 80
#define TIME_OUT 5
#define MAX_REQUEST_LENGTH 512
#define MAX_RESPONSE_LENGTH 1024


/*
  httpd.c
  A simple HTTP/1.0 server.
*/


int serve(void);
int response(void);
int write_header(char *buffer);
int write_body(char *buffer);


static void alarm_handler(int sig) {
    /* just return to interrupt */
}


int main(void) {

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

    if (tcp_socket() != 0) {
        fprintf(stderr, "HTTPD: Opening socket failed\n");
        return 1;
    }

    while (serve()) { }

    printf("Listening failed.\n");

    return 1;

}


int serve(void) {

    char request_buffer[MAX_REQUEST_LENGTH];
    ipaddr_t saddr;

    if (tcp_listen(LISTEN_PORT, &saddr) < 0) {
        return 0;
    }

    signal(SIGALRM, alarm_handler);
    alarm(TIME_OUT);
    if (tcp_read(request_buffer, MAX_REQUEST_LENGTH) < 1) {
        return 1;
    }
    alarm(0);

    if (!response()) {
        return 1;
    }

    if (tcp_close() != 0) {
        return 0;
    }

    signal(SIGALRM, alarm_handler);
    alarm(TIME_OUT);
    while (tcp_read(request_buffer, MAX_REQUEST_LENGTH) > 0) {}
    alarm(0);

    return 1;

}


int response(void) {

    char response_buffer[MAX_RESPONSE_LENGTH];
    int response_length = 0;

    response_length += write_header(response_buffer + response_length);
    response_length += write_body(response_buffer + response_length);

    if (tcp_write(response_buffer, response_length) != response_length) {
        return 0;
    }

    return 1;

}


int write_header(char *buffer) {

    /* I think the -1 is needed here because we don't want a \0 in the buffer...?? */
    return sprintf(buffer, "%s %d %s\nContent-Type: %s\n\n", "HTTP/1.0", 200, "OK", "text/plain") - 1;

}


int write_body(char *buffer) {

    char *file = "./test_response";
    FILE *fp;
    int byte;
    int size = 0;

    fp = fopen(file, "r");

    /*
      Actually, MAX_RESPONSE_LENGTH also includes header size, so this
      check on size is not correct ;)
    */

    while (
        ((byte = getc(fp)) != EOF)
        && (size < MAX_RESPONSE_LENGTH)
        ) {
        size++;
        sprintf(buffer + size, "%c", byte);
        printf("hier eentje\n");
    }

    /*
      This seems ok, but in the tests I'm not sure if the last byte
      of the file is transfered correctly...

      Also, there are many ways to read a file. This does it byte by
      byte (as it was the first method I got working properly).
      Warning: some methods are no option because they can't handle
      null bytes for example (e.g. fgets).
    */

    return size;

}

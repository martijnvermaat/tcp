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
  'length' or 'len' (for ALL code).
*/
#define LISTEN_PORT 80
#define TIME_OUT 5
#define MAX_REQUEST_LENGTH 512
#define MAX_RESPONSE_LENGTH 1024
#define PROTOCOL "HTTP/1.0"

typedef enum {
    STATUS_OK
} http_status;

typedef enum {
    HEADER_CONTENT_TYPE
} http_header;


/*
  httpd.c
  A simple HTTP/1.0 server.
*/


int serve(void);
int response(void);
int write_status(char *buffer, http_status status);
int write_header(char *buffer, http_header header, char *value);
int write_body(char *buffer);


static void alarm_handler(int sig) {
    /* just return to interrupt */
}


int main(int argc, char** argv) {

    char *eth, *ip1, *ip2;

    if (argc < 2) {
        printf("No www dir specified.\n");
        return 1;
    }

    if (chdir(argv[1]) < 0) {
        printf("Could not change dir to '%s'.\n", argv[1]);
        return 1;
    }

    eth = getenv("ETH");
    if (!eth) {
        printf("The ETH environment variable must be set!\n");
        return 1;
    }

    ip1 = getenv("IP1");
    ip2 = getenv("IP2");
    if ((!ip1)||(!ip2)) {
        printf("The IP1 and IP2 environment variables must be set!\n");
        return 1;
    }

    if (tcp_socket() != 0) {
        printf("HTTPD: Opening socket failed\n");
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

    response_length += write_status(response_buffer + response_length, STATUS_OK);

    response_length += write_header(response_buffer + response_length, HEADER_CONTENT_TYPE, "text/plain");
    response_length += write_header(response_buffer + response_length, HEADER_CONTENT_TYPE, "text/html");
    response_length += write_header(response_buffer + response_length, HEADER_CONTENT_TYPE, "application/xhtml+xml");

    response_length += write_body(response_buffer + response_length);

    if (tcp_write(response_buffer, response_length) != response_length) {
        return 0;
    }

    return 1;

}


int write_status(char *buffer, http_status status) {

    char *status_string;
    int status_code;

    if (status == STATUS_OK) {
        status_string = "OK";
        status_code = 200;
    } else {
        return 0;
    }

    return sprintf(buffer, "%s %d %s\n", PROTOCOL, status_code, status_string);

}


int write_header(char *buffer, http_header header, char *value) {

    char *header_string;

    if (header == HEADER_CONTENT_TYPE) {
        header_string = "Content-Type";
    } else {
        return 0;
    }

    return sprintf(buffer, "%s: %s\n", header_string, value);

}


int write_body(char *buffer) {

    char *file = "./test_response";
    FILE *fp;
    int byte;
    int size = 0;

    size += sprintf(buffer + size, "\n");

    fp = fopen(file, "r");

    /*
      Actually, MAX_RESPONSE_LENGTH also includes header size, so this
      check on size is not correct ;)
    */

    while (
        ((byte = getc(fp)) != EOF)
        && (size < MAX_RESPONSE_LENGTH)
        ) {
        size += sprintf(buffer + size, "%c", byte);
        printf("hier eentje\n");
    }

    return size;

}

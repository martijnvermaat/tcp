#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include "tcp.h"


/*
  httpd.c
  A tiny HTTP/1.0 server.

  See http://www.w3.org/Protocols/HTTP/1.0/draft-ietf-http-spec.html
  for a reference guide.
*/


/*
  Decide if we use 'size' or 'length' or 'len' (for ALL code).
  Also for 'chars' and 'bytes'. (Be consistent.)
*/
#define LISTEN_PORT 80
#define TIME_OUT 5
#define MAX_REQUEST_LENGTH 512
#define MAX_RESPONSE_LENGTH 1024
#define PROTOCOL "HTTP/1.0"

typedef enum {
    METHOD_GET, METHOD_HEAD, METHOD_POST, METHOD_PUT,
    METHOD_DELETE, METHOD_EDIT, METHOD_OPTIONS,
    METHOD_TRACE, METHOD_UNKNOWN
} http_method;

typedef enum {
    PROTOCOL_HTTP10, PROTOCOL_HTTP11, PROTOCOL_UNKNOWN
} http_protocol;

typedef enum {
    STATUS_OK
} http_status;

typedef enum {
    HEADER_CONTENT_TYPE, HEADER_SERVER, HEADER_ISLAND
} http_header;


int serve(void);
int parse_request(char *request, int request_length, http_method *method, char *url, http_protocol *protocol, char *headers);
int read_token(char *buffer, int buffer_length, char *token);
int count_spaces(char *buffer, int buffer_length);
int response(void);
int write_status(char *buffer, http_status status);
int write_header(char *buffer, http_header header, char *value);
int write_body(char *buffer);


static void alarm_handler(int sig) {
    /* just return to interrupt */
}


/* 1 on failure, no return on success */

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


/* 1 on success, 0 on failure */

int serve(void) {

    char request_buffer[MAX_REQUEST_LENGTH];
    int request_length;
    ipaddr_t saddr;

    http_method method;
    http_protocol protocol;
    char *url;
    char *headers;

    if (tcp_listen(LISTEN_PORT, &saddr) < 0) {
        return 0;
    }

    signal(SIGALRM, alarm_handler);
    alarm(TIME_OUT);
    request_length = tcp_read(request_buffer, MAX_REQUEST_LENGTH);
    alarm(0);

    if (request_length < 1) {
        return 1;
    }

    if (parse_request(request_buffer, request_length, &method, url, &protocol, headers)) {
        response();
    } else {
        /* 400 bad request (i think) */
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


/* 1 on success, 0 on failure */

int parse_request(char *request, int request_length, http_method *method, char *url, http_protocol *protocol, char *headers) {

    char *protocol_string;
    char *method_string;

    int length = 0;
    int i;

    if (count_spaces(request, request_length - length) > 0) {
        return 0;
    }

    i = read_token(request + length, request_length - length, method_string);
    if (i < 1) {
        return 0;
    }

    /* use strcasecmp for case INsensitive matching... */
    if (strcmp(method_string, "GET") == 0) {
        *method = METHOD_GET;
    } else if (strcmp(method_string, "POST") == 0) {
        *method = METHOD_POST;
    } else {
        *method = METHOD_UNKNOWN;
    }

    if (count_spaces(request + length, request_length - length) != 1) {
        return 0;
    }
    length += i + 1;

    i = read_token(request + length, request_length - length, url);
    if (i < 1) {
        return 0;
    }

    if (count_spaces(request + length, request_length - length) != 1) {
        return 0;
    }
    length += i + 1;

    i = read_token(request + length, request_length - length, protocol_string);
    if (i < 1) {
        return 0;
    }

    if (strcmp(protocol_string, "HTTP/1.0") == 0) {
        *protocol = PROTOCOL_HTTP10;
    } else if (strcmp(protocol_string, "HTTP/1.1") == 0) {
        *protocol = PROTOCOL_HTTP11;
    } else {
        *protocol = PROTOCOL_UNKNOWN;
    }

    length += i;

    /* we should find a \r\n now */

    return 1;

}


/* length of token */

int read_token(char *buffer, int buffer_length, char *token) {

    int i;

    for (i=0; (i < buffer_length) && (buffer[i] != ' ') && (buffer[i] != '\r'); i++) {}

    /* the memcpy segfaults... */
    memcpy(token, buffer, i);
    token[i] = '\0';

    return i;

}


/* number of spaces */

int count_spaces(char *buffer, int buffer_length) {

    int i;

    for (i=0; (i < buffer_length) && (buffer[i] == ' '); i++) {}

    return i;

}


/* 1 on success, 0 on failure */

int response(void) {

    char response_buffer[MAX_RESPONSE_LENGTH];
    int response_length = 0;

    response_length += write_status(response_buffer + response_length, STATUS_OK);

    response_length += write_header(response_buffer + response_length, HEADER_CONTENT_TYPE, "text/plain");
    response_length += write_header(response_buffer + response_length, HEADER_CONTENT_TYPE, "text/html");
    response_length += write_header(response_buffer + response_length, HEADER_ISLAND, "Goeree Overflakkee");
    response_length += write_header(response_buffer + response_length, HEADER_SERVER, "Tiny httpd.c / 0.1 (maybe on Minix)");

    response_length += write_body(response_buffer + response_length);

    if (tcp_write(response_buffer, response_length) != response_length) {
        return 0;
    }

    return 1;

}


/* number of bytes written */

int write_status(char *buffer, http_status status) {

    char *status_string;
    int status_code;

    if (status == STATUS_OK) {
        status_string = "OK";
        status_code = 200;
    } else {
        return 0;
    }

    return sprintf(buffer, "%s %d %s\r\n", PROTOCOL, status_code, status_string);

}


/* number of bytes written */

int write_header(char *buffer, http_header header, char *value) {

    char *header_string;

    if (header == HEADER_CONTENT_TYPE) {
        header_string = "Content-Type";
    } else if (header == HEADER_SERVER) {
        header_string = "Server";
    } else if (header == HEADER_ISLAND) {
        header_string = "Nice-Island";
    } else {
        return 0;
    }

    return sprintf(buffer, "%s: %s\r\n", header_string, value);

}


/* number of bytes written */

int write_body(char *buffer) {

    char *file = "tisvu";
    FILE *fp;
    int byte;
    int size = 0;

    size += sprintf(buffer + size, "\r\n");

    /*
      More error checking here if opening file goes well.
      Also, we should check permissions, as we should always
      return a Permission Denied on files not world-readable.
      Re-read the guide for this some time...
    */
    fp = fopen(file, "r");

    /*
      Actually, MAX_RESPONSE_LENGTH also includes header size, so this
      check on size is not correct at all ;)
    */
    while (
        ((byte = getc(fp)) != EOF)
        && (size < MAX_RESPONSE_LENGTH)
        ) {
        size += sprintf(buffer + size, "%c", byte);
    }

    return size;

}

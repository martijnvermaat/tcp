#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <signal.h>
#include "tcp.h"


/*
  httpc.c
  A tiny HTTP/1.0 client.

  See http://www.w3.org/Protocols/HTTP/1.0/draft-ietf-http-spec.html
  for a reference guide.
*/


#define SERVER_PORT 80
#define TIME_OUT 10
#define REQUEST_BUFFER_SIZE 512
#define RESPONSE_BUFFER_SIZE 1024 /* response header should always fit */
#define PROTOCOL "HTTP/1.0"
#define VERSION "Tiny httpc.c/1.0 ({lmbronwa,mvermaat}@cs.vu.nl)"


int do_request(char *ip, char *filename);
int handle_response(char *ip, char *filename);
int parse_url(char *url, char **ip, char **filename);
int parse_status_line(char **status_line, int *status_ok);
int parse_header(char **header, char **value);
int read_separator(void);
int add_to_buffer(void);


static char response_buffer[RESPONSE_BUFFER_SIZE];
static int response_length = 0;
static int response_pointer = 0;
static int alarm_went_off = 0;


static void alarm_handler(int sig) {
    /* just return to interrupt */
    printf("httpc alarm went off\n");
    alarm_went_off = 1;
}


/* 0 on success, otherwise failure */

int main(int argc, char** argv) {

    char *eth, *ip1, *ip2;

    char *ip;
    char *filename;

    if (argc < 2) {
        printf("No url found\nUsage: %s url\n", argv[0]);
        return 1;
    }

    eth = getenv("ETH");
    if (!eth) {
        fprintf(stdout, "The ETH environment variable must be set!\n");
        return 1;
    }

    ip1 = getenv("IP1");
    ip2 = getenv("IP2");
    if ((!ip1)||(!ip2)) {
        fprintf(stdout, "The IP1 and IP2 environment variables must be set!\n");
        return 1;
    }

    if (tcp_socket() != 0) {
        fprintf(stdout, "HTTPC: Opening socket failed\n");
        return 1;
    }

    /* parse url into ip and filename */
    if (!parse_url(argv[1], &ip, &filename)) {
        printf("Invalid url: %s\n", argv[1]);
        return 1;
    }

    /* connect to http server */
    if (tcp_connect(inet_aton(ip), SERVER_PORT)) {
        printf("Request failed: could not connect to server\n");
        return 0;
    }

    /* do request */
    if (!do_request(ip, filename)) {
        tcp_close();
        return 1;
    }

    /* handle response */
    if (!handle_response(ip, filename)) {
        tcp_close();
        return 1;
    }

    /* close connection */
    if (tcp_close() != 0) {
        printf("Closing connection failed\n");
        return 1;
    }

    signal(SIGALRM, alarm_handler);
    alarm(TIME_OUT);
    while (tcp_read(response_buffer, RESPONSE_BUFFER_SIZE) > 0) {}
    alarm(0);

    return 0;

}


/* 1 on success, 0 on failure */

int do_request(char *ip, char *filename) {

    char request_buffer[REQUEST_BUFFER_SIZE];
    int request_length;

    int sent = 0;
    int total_sent = 0;

    /* create request */
    request_length = snprintf(request_buffer,
                              REQUEST_BUFFER_SIZE,
                              "GET /%s %s\r\nUser-Agent: %s\r\n\r\n",
                              filename, PROTOCOL, VERSION);

    if ((request_length < 0)
        || (request_length >= REQUEST_BUFFER_SIZE)) {
        printf("Filename too long: %s\n", filename);
        return 0;
    }

    /* send request */
    do {
        sent = tcp_write(request_buffer + total_sent, request_length - total_sent);
        total_sent += sent;
    } while ((sent > 0) && total_sent < request_length);

    /* sending data failed */
    if (sent <= 0) {
        printf("Request failed: could not send request to server\n");
        return 0;
    }

    return 1;

}


/* 1 on success, 0 on failure */

int handle_response(char *ip, char *filename) {

    char *status_line;
    char *header;
    char *value;
    int status_ok;

    char *header_content_length = "Unknown";
    char *header_content_type = "Unknown";
    char *header_last_modified = "Unknown";

    time_t curtime;
#define TIME_LENGTH 32
    char current_time[TIME_LENGTH];

    FILE *fp;

    /* fill buffer with first part of response */
    if (!add_to_buffer()) {
        printf("Request failed: could not retrieve response from server\n");
        return 0;
    }

    /*
      Be carefull to not use the buffer contents after they have been
      overwritten. We assume the entire header fits in the buffer at
      one time, so we can reference to header fields untill we call
      add_to_buffer for reading more of the body.
    */

    /* read status line */
    if (!parse_status_line(&status_line, &status_ok)) {
        printf("Request failed: invalid response status code sent by server\n");
        return 0;
    }

    /* read headers */
    while (parse_header(&header, &value)) {
        if (strcmp(header, "Content-Length") == 0) {
            header_content_length = value;
        } else if (strcmp(header, "Content-Type") == 0) {
            header_content_type = value;
        } else if (strcmp(header, "Last-Modified") == 0) {
            header_last_modified = value;
        }
    }

    if (!read_separator()) {
        printf("Request failed: invalid response sent by server\n");
        return 0;
    }

    /* get current time */
    time(&curtime);
    strftime(current_time, TIME_LENGTH, "%a, %d %b %Y %H:%M:%S GMT", gmtime(&curtime));

    printf("Request sent to http server at %s. Received response:\n", ip);
    printf("  The return code was:        %s\n", status_line);
    printf("  Date of retrieval:          %s\n", current_time);
    printf("  Document last modified at:  %s\n", header_last_modified);
    printf("  Document size:              %s bytes\n", header_content_length);
    printf("  Document's mime type:       %s\n", header_content_type);

    if (!status_ok) {
        printf("Since the status code was not '200 OK', no data has been written\nto %s\n", filename);
        return 1;
    }

    /* check for message body */
    if (response_length <= response_pointer) {
        printf("No message body was present\n");
        return 1;
    }

    /* open file for writing */
    if ((fp = fopen(filename, "w")) == (FILE *)0) {
        printf("Could not open file for writing: %s\n", filename);
        return 0;
    }

    do {

        /* write buffer contents to file */
        while (response_pointer < response_length) {
            putc(response_buffer[response_pointer], fp);
            response_pointer++;
        }

        /* refill buffer if it was filled completely */
        /*
          todo: this is a nasty bug. the idea is that we
          expect more data when de buffer is completely
          filled. but in theory it could be the case that
          one buffer is EXACTLY the amount of data there
          is to read. in that case, we do another
          tcp_read which might fail and we assume we
          miss part of the data. how to solve this?
        */
        if (response_length == RESPONSE_BUFFER_SIZE) {
            response_length = 0;
            if (!add_to_buffer()) {
                /*
                  Actually, we should write to a temp file
                  and delete it here. Only if all data is
                  received, copy temp file to real file.
                  But this is a problem if we have write
                  rights on filename, but not to create
                  temp file. So we leave this for the time
                  being.                  
                */
                fclose(fp);
                printf("Request failed: could not retrieve message body\n");
                printf("Wrote partial message body to file: %s\n", filename);
                return 0;
            }
        } else {
            response_length = 0;
        }

        response_pointer = 0;

    } while (response_length);

    fclose(fp);

    printf("Wrote message body to file: %s\n", filename);

    return 1;

}


/* 1 on success, 0 on failure */

int parse_url(char *url, char **ip, char **filename) {

    char *p = url;

    if (strlen(url) < 8) {
        return 0;
    }

    /* advance to last '/' of protocol */
    p += 6;

    /* mark end of protocol */
    if (*p != '/') {
        return 0;
    }
    *p = '\0';

    if (strcmp(url, "http:/") != 0) {
        return 0;
    }

    p++;

    /* start of ip */
    *ip = p;

    /* read ip */
    while (*p && *p != '/') p++;

    /* end of ip */
    if (*p != '/') {
        return 0;
    }
    *p = '\0';

    p++;

    /* start of filename */
    *filename = p;

    /* check for empty filename */
    if (*p == '\0') {
        return 0;
    }

    return 1;

}


/* 1 on success, 0 on failure */

int parse_status_line(char **status_line, int *status_ok) {

    char *protocol;

    /* read spaces */
    while ((response_pointer < response_length)
           && (response_buffer[response_pointer] == ' ')) {
        response_pointer++;
    }

    /* start of protocol */
    protocol = response_buffer + response_pointer;

    /* read protocol */
    while ((response_pointer < response_length)
           && (response_buffer[response_pointer] != ' ')) {
        response_pointer++;
    }

    /* check end of buffer */
    if (response_pointer >= response_length) return 0;

    /* NULL terminate protocol */
    response_buffer[response_pointer] = '\0';
    response_pointer++;

    /* check for HTTP 1.0 protocol */
    if (strcmp(protocol, PROTOCOL) != 0) {
        return 0;
    }

    /* read spaces */
    while ((response_pointer < response_length)
           && (response_buffer[response_pointer] == ' ')) {
        response_pointer++;
    }

    /* start of status */
    *status_line = response_buffer + response_pointer;

    /* read status number */
    while ((response_pointer < response_length)
           && (response_buffer[response_pointer] != ' ')) {
        response_pointer++;
    }

    /* check end of buffer */
    if (response_pointer >= response_length) return 0;

    /* NULL terminate status number */
    response_buffer[response_pointer] = '\0';

    /* check for happiness */
    if (strcmp(*status_line, "200") == 0) {
        /* this is happy enough */
        *status_ok = 1;
    } else {
        *status_ok = 0;
    }

    /* put space back, we need the original status line */
    response_buffer[response_pointer] = ' ';
    response_pointer++;

    /* read status line */
    while ((response_pointer < response_length)
           && (response_buffer[response_pointer] != '\r')) {
        response_pointer++;
    }

    /* skip to '\n' */
    response_pointer++;

    /* check end of buffer */
    if (response_pointer >= response_length) return 0;

    if (response_buffer[response_pointer] != '\n') {
        return 0;
    }

    /* end of status line */
    response_buffer[response_pointer-1] = '\0';

    response_pointer++;

    if (response_pointer >= response_length) {
        return 0;
    }

    return 1;

}


/* 1 on succes, 0 on failure */

int parse_header(char **header, char **value) {

    /* read spaces */
    while ((response_pointer < response_length)
           && (response_buffer[response_pointer] == ' ')) {
        response_pointer++;
    }

    /* check for end of buffer */
    if (response_pointer >= response_length) {
        return 0;
    }

    /* check for \r */
    if (response_buffer[response_pointer] == '\r') {
        return 0;
    }

    /* start of header name */
    *header = response_buffer + response_pointer;

    /* read header name */
    while ((response_pointer < response_length)
           && (response_buffer[response_pointer] != ':')) {
        response_pointer++;
    }

    /* check for end of buffer */
    if (response_pointer >= response_length) {
        return 0;
    }

    /* end of header name */
    response_buffer[response_pointer] = '\0';
    response_pointer++;

    /* read spaces */
    while ((response_pointer < response_length)
           && (response_buffer[response_pointer] == ' ')) {
        response_pointer++;
    }

    /* start of header value */
    *value = response_buffer + response_pointer;

    /* read header value */
    while ((response_pointer < response_length)
           && (response_buffer[response_pointer] != '\r')) {
        response_pointer++;
    }

    /* skip to '\n' */
    response_pointer++;

    /* check for end of buffer */
    if (response_pointer >= response_length) {
        return 0;
    }

    if (response_buffer[response_pointer] != '\n') {
        return 0;
    }

    /* end of header value */
    response_buffer[response_pointer-1] = '\0';
    response_pointer++;

    return 1;

}


/* 1 on succes, 0 on failure */

int read_separator(void) {

    /* check for end of buffer */
    if ((response_pointer+1) >= response_length) {
        return 0;
    }

    /* check for \r\n */
    if ((response_buffer[response_pointer] != '\r')
        && (response_buffer[response_pointer+1] != '\n')) {
        return 0;
    }

    /* advance pointer to body */
    response_pointer += 2;

    return 1;

}


/* 1 on success, 0 on failure */

int add_to_buffer(void) {

    int length = 0;

    if (response_length >= RESPONSE_BUFFER_SIZE) {
        return 1;
    }

    signal(SIGALRM, alarm_handler);
    alarm(TIME_OUT);
    length = tcp_read(response_buffer + response_length,
                      RESPONSE_BUFFER_SIZE - response_length);
    alarm(0);

    if ((length < 0) || alarm_went_off) {
        return 0;
    }

    response_length += length;

    return 1;

}

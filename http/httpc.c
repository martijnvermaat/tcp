#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
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
#define DATE_TIME_FORMAT "%a, %d %b %Y %H:%M:%S GMT"
#define PROTOCOL "HTTP/1.0"
#define VERSION "Tiny httpc.c/1.0 ({lmbronwa,mvermaat}@cs.vu.nl)"

#define REQUEST_BUFFER_SIZE 512  /* request should fit */
#define RESPONSE_BUFFER_SIZE 1024  /* response header should always fit */
#define IP_LENGTH 18
#define FILENAME_LENGTH 255
#define HEADER_LINE_LENGTH 200  /* used for a lot of small temporary buffers */


int do_request(char *ip, char *filename);
int handle_response(char *ip, char *filename);
int get_response_header(char *buffer, int max_length);
int parse_url(char *url, char *ip, int ip_length, char *filename, int filename_length);
int file_name_character(int c);
int parse_status_line(char *buffer, int buffer_size, char *status_line, int status_line_length, int *status_ok);
int parse_header(char *buffer, int buffer_size, char *header, int header_length, char *value, int value_length);
int read_separator(char *buffer, int buffer_size);


static int alarm_went_off = 0;


static void alarm_handler(int sig) {
    /* just return to interrupt */
    alarm_went_off = 1;
}


/* 0 on success, otherwise failure */

int main(int argc, char** argv) {

    char *eth, *ip1, *ip2;

    char ip[IP_LENGTH];
    char filename[FILENAME_LENGTH];

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
    if (!parse_url(argv[1], ip, IP_LENGTH, filename, FILENAME_LENGTH)) {
        printf("Invalid url\n");
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

/*
    signal(SIGALRM, alarm_handler);
    alarm(TIME_OUT);
    while (tcp_read(response_buffer, RESPONSE_BUFFER_SIZE) > 0) {}
    alarm(0);
*/

    return 0;

}


/* 1 on success, 0 on failure */

int do_request(char *ip, char *filename) {

    char request_buffer[REQUEST_BUFFER_SIZE];
    int request_length;

    int sent = 0;

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
    sent = tcp_write(request_buffer, request_length);

    /* sending data failed */
    if (sent != request_length) {
        printf("Request failed: could not send request to server\n");
        return 0;
    }

    return 1;

}


/* 1 on success, 0 on failure */

int handle_response(char *ip, char *filename) {

    int i;

    char buffer[RESPONSE_BUFFER_SIZE];
    int buffer_size = 0;
    int pointer = 0;

    char status_line[HEADER_LINE_LENGTH];
    char header[HEADER_LINE_LENGTH];
    char value[HEADER_LINE_LENGTH];
    int status_ok;

    char header_content_length[HEADER_LINE_LENGTH];// = "Unknown";
    char header_content_type[HEADER_LINE_LENGTH]; // = "Unknown";
    char header_last_modified[HEADER_LINE_LENGTH];// = "Unknown";

    time_t curtime;
#define TIME_LENGTH 32
    char current_time[TIME_LENGTH];

    FILE *fp;

    /* fill buffer with first part of response */
    buffer_size = get_response_header(buffer, RESPONSE_BUFFER_SIZE);
    if (buffer_size < 0) {
        printf("Request failed: could not retrieve response from server\n");
        return 0;
    }

    /* read status line */
    pointer = parse_status_line(buffer, buffer_size, status_line, HEADER_LINE_LENGTH, &status_ok);
    if (pointer < 0) {
        printf("Request failed: invalid response status code sent by server\n");
        return 0;
    }

    /* default value for headers */
    snprintf(header_content_length, HEADER_LINE_LENGTH, "Unknown");
    snprintf(header_content_type, HEADER_LINE_LENGTH, "Unknown");
    snprintf(header_last_modified, HEADER_LINE_LENGTH, "Unknown");

    /* read headers */
    while ((i = parse_header(buffer + pointer, buffer_size - pointer,
                             header, HEADER_LINE_LENGTH,
                             value, HEADER_LINE_LENGTH)) > 0) {
        pointer += i;
        if (strcmp(header, "Content-Length") == 0) {
            memcpy(header_content_length, value, HEADER_LINE_LENGTH);
        } else if (strcmp(header, "Content-Type") == 0) {
            memcpy(header_content_type, value, HEADER_LINE_LENGTH);
        } else if (strcmp(header, "Last-Modified") == 0) {
            memcpy(header_last_modified, value, HEADER_LINE_LENGTH);
        }
    }

    i = read_separator(buffer + pointer, buffer_size - pointer);
    if (i < 0) {
        printf("Request failed: invalid response sent by server\n");
        return 0;
    }
    pointer += i;

    /* get current time */
    time(&curtime);
    strftime(current_time, TIME_LENGTH, DATE_TIME_FORMAT, gmtime(&curtime));

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

    /* open file for writing */
    if ((fp = fopen(filename, "w")) == (FILE *)0) {
        switch (errno) {
            case EACCES:
                printf("No permissions to open file for writing: %s\n", filename);
                return 0;
                break;
            default:
                printf("Could not open file for writing: %s\n", filename);
                return 0;
        }
    }

    do {

        /* write buffer contents to file */
        while (pointer < buffer_size) {
            putc(buffer[pointer], fp);
            pointer++;
        }

        signal(SIGALRM, alarm_handler);
        alarm(TIME_OUT);
        buffer_size = tcp_read(buffer, RESPONSE_BUFFER_SIZE);
        alarm(0);

        /* failed reading */
        if ((buffer_size < 0) || alarm_went_off) {
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

        pointer = 0;

    } while (buffer_size);

    fclose(fp);

    printf("Wrote message body to file: %s\n", filename);

    return 1;

}


/* number of bytes read on success, -1 on failure */

int get_response_header(char *buffer, int max_length) {

    int length;
    int total_length = 0;
    int header_complete = 0;

    /* do tcp_read until we find \r\n\r\n in buffer */

    do {

        signal(SIGALRM, alarm_handler);
        alarm(TIME_OUT);
        length = tcp_read(buffer + total_length,
                          max_length - total_length);
        alarm(0);

        /* could not read any more bytes */
        if ((length < 1) || alarm_went_off) {
            return -1;
        }

        /* byte by byte search for '\r' */
        while (length > 0) {

            if (buffer[total_length] == '\r') {

                if (header_complete == 0
                    || header_complete == 2) {
                    header_complete++;
                } else {
                    header_complete = 0;
                }

            } else if (buffer[total_length] == '\n') {

                if (header_complete == 1
                    || header_complete == 3) {
                    header_complete++;
                } else {
                    header_complete = 0;
                }

            } else {

                header_complete = 0;

            }

            if (header_complete == 4) {
                break;
            }

            total_length++;
            length--;

        }

        total_length += length;

    } while (header_complete < 4);

    return total_length;

}


/* 1 on success, 0 on failure */

int parse_url(char *url, char *ip, int ip_length, char *filename, int filename_length) {

    char *ip_string;
    char *filename_string;
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
    ip_string = p;

    /* read ip */
    while (*p && *p != '/') p++;

    /* end of ip */
    if (*p != '/') {
        return 0;
    }
    *p = '\0';

    p++;

    /* start of filename */
    filename_string = p;

    /* check for empty filename */
    if (*p == '\0') {
        return 0;
    }

    /* check for valid filename */
    while (*p) {
        if (!file_name_character(*p)) {
            return 0;
        }
        p++;
    }

    /* copy ip */
    if (strlen(ip_string) >= ip_length) {
        return 0;
    }
    memcpy(ip, ip_string, strlen(ip_string) + 1);

    /* copy ip */
    if (strlen(filename_string) >= filename_length) {
        return 0;
    }
    memcpy(filename, filename_string, strlen(filename_string) + 1);

    return 1;

}


/* 1 if char is valid in filename, 0 otherwise */

int file_name_character(int c) {

    /*
      We are being a bit conservative here with
      the characters we accept in a filename.
      It never hurts to handle data for a system
      call (fopen) like a paranoid android.
      For the moment, it takes too much time to
      figure out exactly which characters are
      valid in a filename on the current OS,
      hope you don't mind...
    */

    return (isalnum(c)
            || c == '.'
            || c == ','
            || c == '-'
            || c == '_'
            || c == '#'
            || c == '+');

}


/* number of bytes parsed on success, -1 on failure */

int parse_status_line(char *buffer, int buffer_size, char *status_line, int status_line_length, int *status_ok) {

    char *protocol;
    int marker;
    int pointer = 0;

    /* read spaces */
    while ((pointer < buffer_size)
           && (buffer[pointer] == ' ')) {
        pointer++;
    }

    /* start of protocol */
    protocol = buffer + pointer;

    /* read protocol */
    while ((pointer < buffer_size)
           && (buffer[pointer] != ' ')) {
        pointer++;
    }

    /* check end of buffer */
    if (pointer >= buffer_size) return -1;

    /* NULL terminate protocol */
    buffer[pointer] = '\0';
    pointer++;

    /* check for HTTP 1.0 protocol */
    if (strcmp(protocol, PROTOCOL) != 0) {
        return -1;
    }

    /* read spaces */
    while ((pointer < buffer_size)
           && (buffer[pointer] == ' ')) {
        pointer++;
    }

    /* start of status */
    marker = pointer;

    /* read status number */
    while ((pointer < buffer_size)
           && (buffer[pointer] != ' ')) {
        pointer++;
    }

    /* check end of buffer */
    if (pointer >= buffer_size) return -1;

    /* NULL terminate status number */
    buffer[pointer] = '\0';
    pointer++;

    /* copy status code */
    if ((pointer - marker) > status_line_length) {
        return -1;
    }
    memcpy(status_line, buffer + marker, (pointer - marker));

    /* check for happiness */
    if (strcmp(status_line, "200") == 0) {
        /* this is happy enough */
        *status_ok = 1;
    } else {
        *status_ok = 0;
    }

    /* put space back, we need the original status line */
    buffer[pointer-1] = ' ';

    /* read status line */
    while ((pointer < buffer_size)
           && (buffer[pointer] != '\r')) {
        pointer++;
    }

    /* skip to '\n' */
    pointer++;

    /* check end of buffer */
    if (pointer >= buffer_size) return -1;

    if (buffer[pointer] != '\n') {
        return -1;
    }

    /* end of status line */
    buffer[pointer-1] = '\0';
    pointer++;

    /* copy status line */
    if ((pointer - marker) > status_line_length) {
        return -1;
    }
    memcpy(status_line, buffer + marker, (pointer - marker));

    if (pointer >= buffer_size) {
        return -1;
    }

    return pointer;

}


/* number of files parsed on succes, -1 on failure */

int parse_header(char *buffer, int buffer_size, char *header, int header_length, char *value, int value_length) {

    int marker;
    int pointer = 0;

    /*
      todo: a \r\n[space] is allowed to continue a
      header on a new line (2.2 Basic Rules in spec)
    */

    /* read spaces */
    while ((pointer < buffer_size)
           && (buffer[pointer] == ' ')) {
        pointer++;
    }

    /* check for end of buffer */
    if (pointer >= buffer_size) {
        return -1;
    }

    /* check for \r */
    if (buffer[pointer] == '\r') {
        return -1;
    }

    /* start of header name */
    marker = pointer;

    /* read header name */
    while ((pointer < buffer_size)
           && (buffer[pointer] != ':')) {
        pointer++;
    }

    /* check for end of buffer */
    if (pointer >= buffer_size) {
        return -1;
    }

    /* end of header name */
    buffer[pointer] = '\0';
    pointer++;

    /* copy header name */
    if ((pointer - marker) > header_length) {
        return -1;
    }
    memcpy(header, buffer + marker, (pointer - marker));

    /* read spaces */
    while ((pointer < buffer_size)
           && (buffer[pointer] == ' ')) {
        pointer++;
    }

    /* start of header value */
    marker = pointer;

    /* read header value */
    while ((pointer < buffer_size)
           && (buffer[pointer] != '\r')) {
        pointer++;
    }

    /* skip to '\n' */
    pointer++;

    /* check for end of buffer */
    if (pointer >= buffer_size) {
        return -1;
    }

    if (buffer[pointer] != '\n') {
        return -1;
    }

    /* end of header value */
    buffer[pointer-1] = '\0';

    /* copy header value */
    if ((pointer - marker) > value_length) {
        return -1;
    }
    memcpy(value, buffer + marker, (pointer - marker));

    pointer++;

    return pointer;

}


/* number of bytes read on succes, -1 on failure */

int read_separator(char *buffer, int buffer_size) {

    int pointer = 0;

    /* check for end of buffer */
    if ((pointer+1) >= buffer_size) {
        return -1;
    }

    /* check for \r\n */
    if ((buffer[pointer] != '\r')
        && (buffer[pointer+1] != '\n')) {
        return -1;
    }

    /* advance pointer to body */
    pointer += 2;

    return pointer;

}

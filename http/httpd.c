#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <pwd.h>
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
#define UNPRIVILIGED_UID 9999 /* =nobody on minix, on linux 1000 is first normal user */
#define TIME_OUT 5
#define MAX_REQUEST_LENGTH 512
#define MAX_RESPONSE_LENGTH 6225
#define PROTOCOL "HTTP/1.0"

typedef enum {
    METHOD_GET, METHOD_HEAD, METHOD_POST, METHOD_PUT,
    METHOD_DELETE, METHOD_EDIT, METHOD_OPTIONS,
    METHOD_TRACE, METHOD_UNKNOWN
} http_method;

typedef enum {
    STATUS_OK, STATUS_HTTP_VERSION_NOT_SUPPORTED,
    STATUS_NOT_IMPLEMENTED, STATUS_PAYMENT_REQUIRED,
    STATUS_BAD_REQUEST, STATUS_NOT_FOUND, STATUS_FORBIDDEN,
    STATUS_INTERNAL_SERVER_ERROR
} http_status;

typedef enum {
    HEADER_CONTENT_TYPE, HEADER_SERVER, HEADER_ISLAND
} http_header;


int serve(void);
int parse_request(char *request, http_method *method, char **url, char **protocol);
int parse_url(char *url, char **filename, char **mimetype);
int read_token(char *buffer, int buffer_length, char *token);
int count_spaces(char *buffer, int buffer_length);
void write_response(char *buffer, http_method method, char *url, char *protocol);
void send_response(char *buffer);
int handle_get(char *buffer, char *url);
int file_name_character(char *c);
int write_status(char *buffer, http_status status);
int write_error(char *buffer, http_status status);
int write_standard_headers(char *buffer);
int write_header(char *buffer, http_header header, char *value);
int write_body(char *buffer);


static void alarm_handler(int sig) {
    /* just return to interrupt */
}


/* 1 on failure, no return on success */

int main(int argc, char** argv) {

    char *eth, *ip1, *ip2;

    if (argc < 2) {
        printf("No www directory found.\nUsage: %s wwwdir\n", argv[0]);
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

    /* if we are superuser, chroot and change effective uid */
    /* do this after opening tcp socket, because we need access to /dev/eth */
    if (geteuid() == 0) {
        if (chroot(argv[1]) < 0) {
            printf("Could not chroot to www directory.\n");
            return 1;
        }
        /*
           this must be seteuid() actually on linux, add a preprocessor
           conditional for this...
           Also, we should call setgid (setegid on linux) too.
           Think about the value of UNPRIVILIGED_UID:
           On minix, nobody is 9999 (gr 99), first user is 10 (gr 3)
           On linux, nobody is 65534 (gr 65533), first user is 1000 (gr 100)
           Some sources say a uid of -2 wraps to 65534 on linux, so being
           effectively user nobody. Check if this really works, and what it
           does on minix. Also think about what to do with the guid in this
           case...
           If we can't sort this out, the alternative is using stat() when
           opening files to check if it is o+r.

           By the way, maybe check this piece of code again, it would be
           the ideal solution (only I can't get it to work):

           struct passwd *nobody;
           if (((nobody = getpwnam("nobody")) == NULL) ||
               setegid(nobody->pw_gid) ||
               seteuid(nobody->pw_uid)) {
               printf("can't change to user nobody.\n");
               exit (1);
           }
        */
        if (setuid(UNPRIVILIGED_UID)) {
            printf("Could not change to user `nobody'.\n");
            return 1;
        }
        printf("Changed root and uid.\n");
    }

    while (serve()) { }

    printf("Listening failed.\n");

    return 1;

}


/* 1 on success, 0 on failure */

int serve(void) {

    char request_buffer[MAX_REQUEST_LENGTH + 1]; /* +1 because we NULL term it */
    char response_buffer[MAX_RESPONSE_LENGTH + 1]; /* +1 because we NULL term it */
    int request_length;
    ipaddr_t saddr;

    http_method method;
    char *url;
    char *protocol;

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

    /* NULL terminate request buffer */
    request_buffer[request_length] = '\0';

    if (parse_request(request_buffer, &method, &url, &protocol)) {
        write_response(response_buffer, method, url, protocol);
    } else {
        write_error(response_buffer, STATUS_BAD_REQUEST);
    }

    send_response(response_buffer);

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

int parse_request(char *request, http_method *method, char **url, char **protocol) {

    char *method_string;

    char *r = request;

    /* read spaces */
    while (*r && *r == ' ') r++;

    /* start of method */
    method_string = r;

    /* read method */
    while (*r && *r != ' ') r++;

    /* check for space */
    if (*r != ' ') return 0;

    /* NULL terminate method */
    *r = '\0';
    r++;

    /* read spaces */
    while (*r && *r == ' ') r++;

    /* start of url */
    *url = r;

    /* read url */
    while (*r && *r != ' ') r++;

    /* check for space */
    if (*r != ' ') return 0;

    /* NULL terminate url */
    *r = '\0';
    r++;

    /* read spaces */
    while (*r && *r == ' ') r++;

    /* start of protocol */
    *protocol = r;

    /* read protocol */
    while (*r && *r != ' ' && *r != '\r') r++;

    /* read line ending */
    if (*r == '\r') {
        /* \r\n directly following protocol */
        *r = '\0';
        r++;
        if (*r != '\n') return 0;
    } else  if (*r == ' ') {
        /* spaces following protocol */
        *r = '\0';
        r++;
        /* read spaces */
        while (*r && *r == ' ') r++;
        /* read \r\n */
        if (*r != '\r' || *(++r) != '\n') return 0;
    } else {
        /* premature end of request */
        return 0;
    }

    /* determine method */
    if (strcmp(method_string, "GET") == 0) {
        *method = METHOD_GET;
    } else if (strcmp(method_string, "POST") == 0) {
        *method = METHOD_POST;
    } else if (strcmp(method_string, "HEAD") == 0) {
        *method = METHOD_HEAD;
    } else {
        *method = METHOD_UNKNOWN;
    }

    return 1;

}


/* 1 on success, 0 on failure */

void write_response(char *buffer, http_method method, char *url, char *protocol) {

    int length = 0;

    /* check for HTTP 1.0 protocol */
    if (strcmp(protocol, "HTTP/1.0") != 0) {
        length += write_error(buffer, STATUS_HTTP_VERSION_NOT_SUPPORTED);
        buffer[length] = '\0';
        return;
    }

    /* add a handle_* procedure for each HTTP method */
    switch (method) {
        case METHOD_GET:
            length += handle_get(buffer, url);
            break;
        default:
            /* unsupported method */
            length += write_error(buffer, STATUS_NOT_IMPLEMENTED);
    }

    buffer[length] = '\0';

    return;

}


/* number of bytes written */

int handle_get(char *buffer, char *url) {

    char *filename;
    char *mimetype;

    FILE *fp;
    int byte;

    int length;

    if (!parse_url(url, &filename, &mimetype)) {
        return write_error(buffer, STATUS_BAD_REQUEST);
    }

    /* open file */
    if ((fp = fopen(filename, "r")) == (FILE *)0) {
        /* could not open file */
        switch (errno) {
            case ENOENT:
                length = write_error(buffer, STATUS_NOT_FOUND);
                break;
            case EACCES:
                length = write_error(buffer, STATUS_FORBIDDEN);
                break;
            default:
                length = write_error(buffer, STATUS_INTERNAL_SERVER_ERROR);
        }
        return length;
    }

    length = write_status(buffer, STATUS_OK);
    length += write_header(buffer + length, HEADER_CONTENT_TYPE, mimetype);
    length += write_standard_headers(buffer + length);

    /* blank line between headers and body */
    length += sprintf(buffer + length, "\r\n");

    /* write file contents to response buffer */
    while (
        ((byte = getc(fp)) != EOF)
        && (length < MAX_RESPONSE_LENGTH)
        ) {
        length += sprintf(buffer + length, "%c", byte);
    }

    /* check if we read entire file */
    if (byte != EOF) {
        /* should we try harder here and send data in several chunks? */
        length = write_error(buffer, STATUS_PAYMENT_REQUIRED);
    }

    return length;

}


/* 1 on success, 0 on failure */

int parse_url(char *url, char **filename, char **mimetype) {

    char *extension;
    char *u = url;

    /*
      We don't support subdirectories or anything fancy
      like that, so we only look for a simple filename.
    */

    /* check for leading slash */
    if (*u != '/') return 0;
    u++;

    /* start of filename */
    *filename = u;
    extension = u;

    /* filename must not be empty */
    if (!(*u)) return 0;

    /* read filename */
    while (*u && file_name_character(u)) {
        /* remember last . in filename */
        if (*u == '.') extension = u;
        u++;
    }

    /* check for end of url */
    if (*u) return 0;

    /* lookup mimetype based on file extension */
    if (*extension == '.') {

        if (strcmp(extension, ".html") == 0) {
            *mimetype = "text/html";
        } else if (strcmp(extension, ".htm") == 0) {
            *mimetype = "text/html";
        } else if (strcmp(extension, ".txt") == 0) {
            *mimetype = "text/plain";
        } else if (strcmp(extension, ".ps") == 0) {
            *mimetype = "application/postscript";
        } else if (strcmp(extension, ".gif") == 0) {
            *mimetype = "image/gif";
        } else if (strcmp(extension, ".jpg") == 0) {
            *mimetype = "image/jpeg";
        } else if (strcmp(extension, ".jpeg") == 0) {
            *mimetype = "image/jpeg";
        } else {
            /* unknown extension */
            *mimetype = "application/octet-stream";
        }

    } else {
        /* no extension */
        *mimetype = "application/octet-stream";
    }

    return 1;

}


/* 1 if char is valid in filename, 0 otherwise */

int file_name_character(char *c) {

    return 1;

}


/* just write everything to tcp */

void send_response(char *buffer) {

    /* maybe we shouldn't make this buffer NULL terminating... */
    int length = strlen(buffer);
    int sent = 0;
    int total_sent = 0;

    do {
        sent = tcp_write(buffer + total_sent, length - total_sent);
        total_sent += sent;
    while (sent && total_sent < length) {

}


/* number of bytes written */

int write_error(char *buffer, http_status status) {

    int length;

    length = write_status(buffer, status);
    length += write_header(buffer + length, HEADER_CONTENT_TYPE, "text/plain");
    length += write_standard_headers(buffer + length, status);

    return length;

}


/* number of bytes written */

int write_status(char *buffer, http_status status) {

    char *status_string;
    int status_code;

    switch (status) {
        case STATUS_OK:
            status_string = "OK";
            status_code = 200;
            break;
        case STATUS_BAD_REQUEST:
            status_string = "Bad Request";
            status_code = 400;
            break;
        case STATUS_PAYMENT_REQUIRED:
            status_string = "Payment required for files this big";
            status_code = 402;
            break;
        case STATUS_FORBIDDEN:
            status_string = "Forbidden";
            status_code = 403;
            break;
        case STATUS_NOT_FOUND:
            status_string = "Not Found";
            status_code = 404;
            break;
        case STATUS_INTERNAL_SERVER_ERROR:
            status_string = "Internal Server Error";
            status_code = 500;
            break;
        case STATUS_HTTP_VERSION_NOT_SUPPORTED:
            status_string = "HTTP Version Not Supported";
            status_code = 505;
            break;
        case STATUS_NOT_IMPLEMENTED:
            status_string = "Not Implemented";
            status_code = 501;
            break;
        default:
            return 0;
    }

    return sprintf(buffer, "%s %d %s\r\n", PROTOCOL, status_code, status_string);

}


/* number of bytes written */

int write_standard_headers(char *buffer) {

    int length;

    length = write_header(buffer, HEADER_ISLAND, "Goeree Overflakkee");
    length += write_header(buffer + length, HEADER_SERVER, "Tiny httpd.c / 0.1 (maybe on Minix)");

    return length;

}


/* number of bytes written */

int write_header(char *buffer, http_header header, char *value) {

    char *header_string;

    switch (header) {
        case HEADER_CONTENT_TYPE:
            header_string = "Content-Type";
            break;
        case HEADER_SERVER:
            header_string = "Server";
            break;
        case HEADER_ISLAND:
            header_string = "Nice-Island";
            break;
        default:
            return 0;
    }

    return sprintf(buffer, "%s: %s\r\n", header_string, value);

}


/* number of bytes written, -1 in case of error */

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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
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
#define KEEP_SERVING 0
#define LISTEN_PORT 80
#define UNPRIVILIGED_UID 9999 /* 9999=nobody on minix, on linux 1000 is first normal user */
#define TIME_OUT 5
#define REQUEST_BUFFER_SIZE 512
#define RESPONSE_BUFFER_SIZE 1024 /* 'minimum number of bytes we like to send in one go' */
#define FILE_BUFFER_SIZE 80000 /* number of bytes to read at a time from a file, should
                                  be at least the size of RESPONSE_BUFFER_SIZE */
#define PROTOCOL "HTTP/1.0"
#define VERSION "Tiny httpd.c/1.0 ({lmbronwa,mvermaat}@cs.vu.nl)"


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
    HEADER_CONTENT_TYPE, HEADER_SERVER, HEADER_ISLAND,
    HEADER_CONTENT_LENGTH, HEADER_LAST_MODIFIED
} http_header;


int serve(void);
int parse_request(char *request, http_method *method, char **url, char **protocol);
int parse_url(char *url, char **filename, char **mimetype);
int write_response(http_method method, char *url, char *protocol);
int send_buffer(void);
int handle_get(char *url);
int file_name_character(char *c);
int write_data(const char *data, int length);
int write_status(http_status status);
int write_error(http_status status);
int write_standard_headers(void);
int write_header(http_header header, char *value);


static char response_buffer[RESPONSE_BUFFER_SIZE];
static int response_buffer_size;


static void alarm_handler(int sig) {
    /* just return to interrupt */
}


/* 1 on failure, no return or 0 on success */

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


#if KEEP_SERVING

    /* keep calling serve() until it fails, then exit with error code */
    while (serve()) { }
    printf("Listening failed.\n");
    return 1;

#else

    /* call serve() and exit */
    return (!serve());

#endif


}


/* 1 on success, 0 on failure */

int serve(void) {

    char request_buffer[REQUEST_BUFFER_SIZE + 1]; /* +1 because we NULL term it */
    int request_length;
    ipaddr_t saddr;

    http_method method;
    char *url;
    char *protocol;

    response_buffer_size = 0;

    if (tcp_listen(LISTEN_PORT, &saddr) < 0) {
        return 0;
    }

    signal(SIGALRM, alarm_handler);
    alarm(TIME_OUT);
    /* read at most REQUEST_BUFFER_SIZE bytes, we won't do
       anything with request bigger than that anyway... */
    request_length = tcp_read(request_buffer, REQUEST_BUFFER_SIZE);
    alarm(0);

    if (request_length < 1) {
        return 1;
    }

    /* NULL terminate request buffer */
    request_buffer[request_length] = '\0';

    if (parse_request(request_buffer, &method, &url, &protocol)) {
        if (!(write_response(method, url, protocol)
              && send_buffer())) {
            return 1;
        }
    } else {
        if (!(write_error(STATUS_BAD_REQUEST)
              && send_buffer())) {
            return 1;
        }
    }

    if (tcp_close() != 0) {
        return 0;
    }

    signal(SIGALRM, alarm_handler);
    alarm(TIME_OUT);
    while (tcp_read(request_buffer, REQUEST_BUFFER_SIZE) > 0) {}
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

int write_response(http_method method, char *url, char *protocol) {

    /* check for HTTP 1.0 protocol */
    if (strcmp(protocol, "HTTP/1.0") != 0) {
        return write_error(STATUS_HTTP_VERSION_NOT_SUPPORTED);
    }

    /* add a handle_* procedure for each HTTP method */
    switch (method) {
        case METHOD_GET:
            return handle_get(url);
            break;
        default:
            /* unsupported method */
            return write_error(STATUS_NOT_IMPLEMENTED);
    }

}


/* 1 on success, 0 on failure */

int handle_get(char *url) {

    char *filename;
    char *mimetype;

    FILE *fp;
    struct stat file_stat;

#define FILESIZE_LENGTH 12
#define LASTMODIFIED_LENGTH 32

    char filesize[FILESIZE_LENGTH];
    char lastmodified[LASTMODIFIED_LENGTH];

    char file_buffer[FILE_BUFFER_SIZE];
    int bytes_read;
    char byte;

    if (!parse_url(url, &filename, &mimetype)) {
        return write_error(STATUS_BAD_REQUEST);
    }

    /* open file */
    if ((fp = fopen(filename, "r")) == (FILE *)0) {
        /* could not open file */
        switch (errno) {
            case ENOENT:
                return write_error(STATUS_NOT_FOUND);
                break;
            case EACCES:
                return write_error(STATUS_FORBIDDEN);
                break;
            default:
                return write_error(STATUS_INTERNAL_SERVER_ERROR);
        }
    }

    /* get file attributes */
    if (stat(filename, &file_stat)) {
        return write_error(STATUS_INTERNAL_SERVER_ERROR);
    }

    snprintf(filesize, FILESIZE_LENGTH, "%ld", (long) file_stat.st_size);

    /* datetime format as in RFC 1123 */
    strftime(lastmodified, LASTMODIFIED_LENGTH, "%a, %d %b %Y %H:%M:%S GMT", gmtime(&file_stat.st_mtime));

    /* write header and header/body seperator */
    if (!(write_status(STATUS_OK)
          && write_header(HEADER_CONTENT_TYPE, mimetype)
          && write_header(HEADER_CONTENT_LENGTH, filesize)
          && write_header(HEADER_LAST_MODIFIED, lastmodified)
          && write_standard_headers()
          && write_data("\r\n", 2))) {
        fclose(fp);
        return 0;
    }

    /* read file contents */
    do {

        bytes_read = 0;

        while ((bytes_read < FILE_BUFFER_SIZE)
               && ((byte = getc(fp)) != EOF)) {
            file_buffer[bytes_read] = byte;
            bytes_read++;
        }

        if (!write_data(file_buffer, bytes_read)) {
            fclose(fp);
            return 0;
        }

    } while (bytes_read == FILE_BUFFER_SIZE);

    /* error occured during reading of file */
    if (ferror(fp)) {
        fclose(fp);
        return write_error(STATUS_INTERNAL_SERVER_ERROR);
    }

    fclose(fp);

    return 1;

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

    /* okay, maybe this is a bit too optimistic... */
    return 1;

}


/* 1 on success, 0 on failure */

int write_error(http_status status) {

    /* we could send some more info in an HTML body here... */

    /* maybe the error occured after some data was already
       written, so reset the buffer */
    response_buffer_size = 0;

    return (write_status(status)
            && write_header(HEADER_CONTENT_TYPE, "text/plain")
            && write_header(HEADER_CONTENT_LENGTH, "0")
            && write_standard_headers());

}


/* 1 on success, 0 on failure */

int write_status(http_status status) {

    char *status_string;
    int status_code;
    int written;

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
        default:
            status_string = "Not Implemented";
            status_code = 501;
    }

    /*
      if it doesn't fit in the buffer, just return failure.
      the entire header should always fit in the buffer
      anyway, so it isn't worth the hassle to send the buffer
      contents first.
      to change this behaviour, just update this procedure
      like write_data.
    */

    written = snprintf(response_buffer + response_buffer_size,
                       RESPONSE_BUFFER_SIZE - response_buffer_size,
                       "%s %d %s\r\n", PROTOCOL, status_code, status_string);

    if ((written < 0)
        || (written >= (RESPONSE_BUFFER_SIZE - response_buffer_size))) {
        response_buffer_size += written;
        return 0;
    }

    response_buffer_size += written;

    return 1;

}


/* 1 on success, 0 on failure */

int write_standard_headers(void) {

    return (write_header(HEADER_ISLAND, "Goeree Overflakkee")
            && write_header(HEADER_SERVER, VERSION));

}


/* 1 on success, 0 on failure */

int write_header(http_header header, char *value) {

    char *header_string;
    int written;

    switch (header) {
        case HEADER_CONTENT_TYPE:
            header_string = "Content-Type";
            break;
        case HEADER_CONTENT_LENGTH:
            header_string = "Content-Length";
            break;
        case HEADER_LAST_MODIFIED:
            header_string = "Last-Modified";
            break;
        case HEADER_SERVER:
            header_string = "Server";
            break;
        case HEADER_ISLAND:
            header_string = "Nice-Island";
            break;
        default:
            return 1;
    }

    /*
      if it doesn't fit in the buffer, just return failure.
      the entire header should always fit in the buffer
      anyway, so it isn't worth the hassle to send the buffer
      contents first.
      to change this behaviour, just update this procedure
      like write_data.
    */

    written = snprintf(response_buffer + response_buffer_size,
                       RESPONSE_BUFFER_SIZE - response_buffer_size,
                       "%s: %s\r\n", header_string, value);

    printf("written: %d\n", written);

    if ((written < 0)
        || (written >= (RESPONSE_BUFFER_SIZE - response_buffer_size))) {
        return 0;
    }

    response_buffer_size += written;

    return 1;

}


/* write bytes to buffer and send buffer if is is full */
/* 1 on success, 0 on failure */

int write_data(const char *data, int length) {

    int write;
    int written = 0;

    while (written < length) {

        /* check for full buffer */
        if ((RESPONSE_BUFFER_SIZE - response_buffer_size) < 1) {
            if (!send_buffer()) return 0;
        }

        /*
          we could do a check here if length-written means a full buffer;
          in that case, don't copy it to the buffer, but send it right
          away. this would prevent copying enormous amounts of data when
          sending big files.
          we should really implement this, it should improve efficiency
          a lot.
        */

        /* determine number of bytes to write */
        if ((length - written) > (RESPONSE_BUFFER_SIZE - response_buffer_size)) {
            write = RESPONSE_BUFFER_SIZE - response_buffer_size;
        } else {
            write = length - written;
        }

        /* copy some bytes to buffer */
        memcpy(response_buffer + response_buffer_size, data + written, write);
        response_buffer_size += write;

        written += write;

    }

    return 1;

}


/* send contents of buffer */
/* 1 on success, 0 on failure */

int send_buffer() {

    int sent = 0;
    int total_sent = 0;

    do {
        sent = tcp_write(response_buffer + total_sent, response_buffer_size - total_sent);
        total_sent += sent;
    } while (sent && total_sent < response_buffer_size);

    /* sending data failed */
    if (!sent) return 0;

    response_buffer_size = 0;

    return 1;

}

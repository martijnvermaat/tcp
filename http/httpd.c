#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include "tcp.h"


/*
  httpd.c
  A tiny HTTP/1.0 server.

  See http://www.w3.org/Protocols/HTTP/1.0/draft-ietf-http-spec.html
  for a reference guide.
*/


/*
  todo: determine which headers are obligatory and which are not!
  todo: think about $IP1, $IP2, and $ETH: I don't think we need
        al these to be set. how will they test our programs?
*/


#define KEEP_SERVING 1
#define LISTEN_PORT 80
#define TIME_OUT 5
#define DATE_TIME_FORMAT "%a, %d %b %Y %H:%M:%S GMT"  /* RFC 1123 */
#define PROTOCOL "HTTP/1.0"
#define VERSION "Tiny httpd.c/1.0 ({lmbronwa,mvermaat}@cs.vu.nl)"

#define REQUEST_BUFFER_SIZE 512  /* the full request header should always fit */
#define RESPONSE_BUFFER_SIZE 80000
#define MAX_PATH_LENGTH 255
#define URL_LENGTH 255
#define PROTOCOL_LENGTH 10
#define MIME_TYPE_LENGTH 50
#define HEADER_LINE_LENGTH 200  /* used for a lot of small temporary buffers */
#define HTML_ERROR_LENGTH 300

#define HTML_ERROR "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\
<html><head><title>Oops</title></head><body><h1>Oops</h1><p>This didn't\
go too well...</p><hr><address>%s at port %d</address></body></html>\n"


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
    HEADER_CONTENT_TYPE, HEADER_SERVER, HEADER_DATE,
    HEADER_CONTENT_LENGTH, HEADER_LAST_MODIFIED
} http_header;


int serve(void);
int make_absolute_path(char *path, char *absolute, int max_length);
int get_request(char *buffer, int max_length);
int parse_request(char *buffer, int buffer_length, http_method *method, char *url, int url_length, char *protocol, int protocol_length);
int parse_url(char *url, char *filename, int filename_length, char *mimetype, int mimetype_length);
int write_response(http_method method, char *url, char *protocol);
int send_buffer(void);
int handle_get(char *url);
int file_name_character(int c);
int write_data(const char *data, int length);
int write_status(http_status status);
int write_error(http_status status);
int write_general_headers(void);
int write_header(http_header header, char *value);


static char response_buffer[RESPONSE_BUFFER_SIZE];
static int response_buffer_size;
static int alarm_went_off = 0;


static void alarm_handler(int sig) {
    /* just return to interrupt */
    printf("httpd alarm went off\n");
    alarm_went_off = 1;
}


/* 1 on failure, no return or 0 on success */

int main(int argc, char** argv) {

    char absolute_path[MAX_PATH_LENGTH];
    char *eth, *ip1, *ip2;

    if (argc < 2) {
        printf("No www directory found\nUsage: %s wwwdir\n", argv[0]);
        return 1;
    }

    if (chdir(argv[1]) < 0) {
        printf("Could not change dir to '%s'\n", argv[1]);
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

    /* if we are superuser, we can chroot for safety */
    if (geteuid() == 0) {
        /* chroot doesn't accept relative paths */
        if (!make_absolute_path(argv[1], absolute_path, MAX_PATH_LENGTH)
            || (chroot(absolute_path) < 0)
            || (chdir("/") < 0)) {
            printf("Could not chroot to www directory\n");
            return 1;
        }
    }


#if KEEP_SERVING

    /* keep calling serve() until it fails, then exit with error code */
    while (serve()) { }
    printf("Listening failed\n");
    return 1;

#else

    /* call serve() and exit */
    return (!serve());

#endif


}


/* absolute path of file with current working dir */
/* 1 on success, 0 on failure */

int make_absolute_path(char *path, char *absolute, int max_length) {

    char cwd[MAX_PATH_LENGTH];
    int length;

    /* check if it will ever fit */
    if (strlen(path) >= max_length) {
        return 0;
    }

    /* check if path is already absolute */
    if (*path == '/') {
        memcpy(absolute, path, strlen(path));
        return 1;
    }

    /* get current working dir */
    if (getcwd(cwd, MAX_PATH_LENGTH) == NULL) {
        return 0;
    }

    /* copy path after current working dir */
    length = snprintf(absolute,
                      max_length,
                      "%s/%s", cwd, path);

    /* check if path was too long */
    if (length >= max_length) {
        return 0;
    }

    return 1;

}


/* 1 on success, 0 on failure */

int serve(void) {

    ipaddr_t saddr;

    char request_buffer[REQUEST_BUFFER_SIZE];
    int request_buffer_size = 0;

    http_method method;
    char url[URL_LENGTH];
    char protocol[PROTOCOL_LENGTH];

    response_buffer_size = 0;
    alarm_went_off = 0;

    if (tcp_listen(LISTEN_PORT, &saddr) < 0) {
        return 0;
    }

    request_buffer_size = get_request(request_buffer, REQUEST_BUFFER_SIZE);

    if (request_buffer_size < 0) {
        tcp_close();
        return 1;
    }

    if (parse_request(request_buffer, request_buffer_size,
                      &method,
                      url, URL_LENGTH,
                      protocol, PROTOCOL_LENGTH)) {
        if (!(write_response(method, url, protocol)
              && send_buffer())) {
            /*
              Don't call tcp_close in case of error,
              because the client may think all data
              was sent correctly because of that.
            */
            return 1;
        }
    } else {
        if (!(write_error(STATUS_BAD_REQUEST)
              && send_buffer())) {
            /*
              Don't call tcp_close in case of error,
              because the client may think all data
              was sent correctly because of that.
            */
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


/* number of bytes read on success, -1 on failure */

int get_request(char *buffer, int max_length) {

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
        if (length < 1
            || alarm_went_off) {
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

int parse_request(char *buffer, int buffer_size, http_method *method, char *url, int url_length, char *protocol, int protocol_length) {

    char *method_string;
    int marker;
    int pointer = 0;

    /* read spaces */
    while ((pointer < buffer_size)
           && (buffer[pointer] == ' ')) {
        pointer++;
    }

    /* start of method */
    method_string = buffer + pointer;

    /* read method */
    while ((pointer < buffer_size)
           && (buffer[pointer] != ' ')) {
        pointer++;
    }

    /* check end of buffer */
    if (pointer >= buffer_size) return 0;

    /* NULL terminate method */
    buffer[pointer] = '\0';
    pointer++;

    /* read spaces */
    while ((pointer < buffer_size)
           && (buffer[pointer] == ' ')) {
        pointer++;
    }

    /* start of url */
    marker = pointer;

    /* read url */
    while ((pointer < buffer_size)
           && (buffer[pointer] != ' ')) {
        pointer++;
    }

    /* check for space */
    if (pointer >= buffer_size) return 0;

    /* end of url, NULL terminate it */
    buffer[pointer] = '\0';
    pointer++;

    /* copy url */
    if ((pointer - marker) > url_length) {
        return 0;
    }
    memcpy(url, buffer + marker, (pointer - marker));

    /* read spaces */
    while ((pointer < buffer_size)
           && (buffer[pointer] == ' ')) {
           pointer++;
    }

    /* start of protocol */
    marker = pointer;

    /* read protocol */
    while ((pointer < buffer_size)
           && (buffer[pointer] != ' ')
           && (buffer[pointer] != '\r')) {
        pointer++;
    }

    /* read line ending */
    if (buffer[pointer] == '\r') {
        /* \r\n directly following protocol */
        buffer[pointer] = '\0';
        pointer++;
        if (buffer[pointer] != '\n') return 0;
    } else  if (buffer[pointer] == ' ') {
        /* spaces following protocol */
        buffer[pointer] = '\0';
        pointer++;
    } else {
        /* premature end of request */
        return 0;
    }

    /* copy protocol */
    if ((pointer - marker) > protocol_length) {
        return 0;
    }
    memcpy(protocol, buffer + marker, (pointer - marker));

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

    /*
      A valid http request should contain the
      body/header separator \r\n, but as we
      don't look for headers anyway, we are
      being nice here to lazy clients and won't
      check for this.
    */

    return 1;

}


/* 1 on success, 0 on failure */

int write_response(http_method method, char *url, char *protocol) {

    /* check for HTTP 1.0 protocol */
    if (strcmp(protocol, PROTOCOL) != 0) {
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

    char filename[MAX_PATH_LENGTH];
    char mimetype[MIME_TYPE_LENGTH];

    FILE *fp;
    struct stat file_stat;

    char filesize[HEADER_LINE_LENGTH];
    char lastmodified[HEADER_LINE_LENGTH];
    time_t curtime;

    char byte;

    if (!parse_url(url,
                   filename, MAX_PATH_LENGTH,
                   mimetype, MIME_TYPE_LENGTH)) {
        return write_error(STATUS_BAD_REQUEST);
    }

    /* get file attributes */
    if (stat(filename, &file_stat)) {
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

    /* check if file is directory */
    if (file_stat.st_mode & S_IFDIR) {
        return write_error(STATUS_FORBIDDEN);
    }

    /* check if file is o+r */
    if (!(file_stat.st_mode & S_IROTH)) {
        return write_error(STATUS_FORBIDDEN);
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

    snprintf(filesize, HEADER_LINE_LENGTH, "%ld", (long) file_stat.st_size);

    /* if lastmodified is in the future, just send the current datetime */
    if (difftime(time(NULL), file_stat.st_mtime) < 0) {
        time(&curtime);
        strftime(lastmodified, HEADER_LINE_LENGTH, DATE_TIME_FORMAT, gmtime(&curtime));
    } else {
        strftime(lastmodified, HEADER_LINE_LENGTH, DATE_TIME_FORMAT, gmtime(&file_stat.st_mtime));
    }

    /* write header and header/body seperator */
    if (!(write_status(STATUS_OK)
          && write_general_headers()
          && write_header(HEADER_CONTENT_TYPE, mimetype)
          && write_header(HEADER_CONTENT_LENGTH, filesize)
          && write_header(HEADER_LAST_MODIFIED, lastmodified)
          && write_data("\r\n", 2))) {
        fclose(fp);
        return 0;
    }

    /* read file contents */
    do {
        byte = getc(fp);
        if (feof(fp)) {
            break;
        }
        if (ferror(fp)) {
            break;
        }
    } while (write_data(&byte, 1));

    /* error occured during reading of file */
    if (ferror(fp)) {
        fclose(fp);
        return write_error(STATUS_INTERNAL_SERVER_ERROR);
    }

    /* error occured during sending of file */
    if (!feof(fp)) {
        fclose(fp);
        return 0;
    }

    fclose(fp);

    return 1;

}


/* 1 on success, 0 on failure */

int parse_url(char *url, char *filename, int filename_length, char *mimetype, int mimetype_length) {

    char *mime;
    char *file;
    char *extension;
    char *u = url;

    /*
      We don't support subdirectories or anything fancy
      like that, so we only look for a simple filename.
    */

    /* check for optional leading slash */
    if (*u == '/') u++;

    /* start of filename */
    file = u;
    extension = u;

    /* filename must not be empty */
    if (!(*u)) return 0;

    /* read filename */
    while (*u && file_name_character(*u)) {
        /* remember last . in filename */
        if (*u == '.') extension = u;
        u++;
    }

    /* check for end of url */
    if (*u) return 0;

    /* lookup mimetype based on file extension */
    if (*extension == '.') {

        if (strcmp(extension, ".html") == 0) {
            mime = "text/html";
        } else if (strcmp(extension, ".htm") == 0) {
            mime = "text/html";
        } else if (strcmp(extension, ".txt") == 0) {
            mime = "text/plain";
        } else if (strcmp(extension, ".ps") == 0) {
            mime = "application/postscript";
        } else if (strcmp(extension, ".gif") == 0) {
            mime = "image/gif";
        } else if (strcmp(extension, ".jpg") == 0) {
            mime = "image/jpeg";
        } else if (strcmp(extension, ".jpeg") == 0) {
            mime = "image/jpeg";
        } else {
            /* unknown extension */
            mime = "application/octet-stream";
        }

    } else {
        /* no extension */
        mime = "application/octet-stream";
    }

    /* copy mimetype */
    if (strlen(mime) >= mimetype_length) {
        return 0;
    }
    memcpy(mimetype, mime, strlen(mime) + 1);

    /* copy filename */
    if (strlen(file) >= filename_length) {
        return 0;
    }
    memcpy(filename, file, strlen(file) + 1);

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


/* 1 on success, 0 on failure */

int write_error(http_status status) {

    time_t curtime;
    char html_error[HTML_ERROR_LENGTH];
    char last_modified[HEADER_LINE_LENGTH];
    char content_length[HEADER_LINE_LENGTH];

    /* maybe the error occured after some data was already
       written, so reset the buffer */
    response_buffer_size = 0;

    /* send current time as lastmodified */
    time(&curtime);
    strftime(last_modified, HEADER_LINE_LENGTH, DATE_TIME_FORMAT, gmtime(&curtime));

    /* content body */
    snprintf(html_error, HTML_ERROR_LENGTH, HTML_ERROR, VERSION, LISTEN_PORT);

    snprintf(content_length, HEADER_LINE_LENGTH, "%d", strlen(html_error));

    return (write_status(status)
            && write_general_headers()
            && write_header(HEADER_CONTENT_TYPE, "text/plain")
            && write_header(HEADER_CONTENT_LENGTH, content_length)
            && write_header(HEADER_LAST_MODIFIED, last_modified)
            && write_data("\r\n", 2)
            && write_data(html_error, strlen(html_error)));

}


/* 1 on success, 0 on failure */

int write_status(http_status status) {

    char status_line[HEADER_LINE_LENGTH];
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

    /* format status line */
    written = snprintf(status_line, HEADER_LINE_LENGTH, "%s %d %s\r\n", PROTOCOL, status_code, status_string);

    if (written >= HEADER_LINE_LENGTH) {
        written = HEADER_LINE_LENGTH -1;
    }

    return write_data(status_line, written);

}


/* 1 on success, 0 on failure */

int write_general_headers(void) {

    char date_value[HEADER_LINE_LENGTH];
    time_t curtime;

    time(&curtime);
    strftime(date_value, HEADER_LINE_LENGTH, DATE_TIME_FORMAT, gmtime(&curtime));

    return (write_header(HEADER_DATE, date_value)
            && write_header(HEADER_SERVER, VERSION));

}


/* 1 on success, 0 on failure */

int write_header(http_header header, char *value) {

    char header_line[HEADER_LINE_LENGTH];
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
        case HEADER_DATE:
            header_string = "Date";
            break;
        default:
            return 1;
    }

    /* format status line */
    written = snprintf(header_line, HEADER_LINE_LENGTH, "%s: %s\r\n", header_string, value);

    if (written >= HEADER_LINE_LENGTH) {
        written = HEADER_LINE_LENGTH -1;
    }

    return write_data(header_line, written);

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

    if (tcp_write(response_buffer, response_buffer_size)
        != response_buffer_size) {
        return 0;
    }

    response_buffer_size = 0;

    return 1;

}

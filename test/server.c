#include <stdio.h>
#include <stdlib.h>
#include "inet.h"
#include "tcp.h"
 
#define THEIR_IP getenv("IP1")
#define OUR_PORT 80


int main(void) {

  int maxlen = 75;
  char data[maxlen+1];
  int len;
  int i = 0;

  ipaddr_t their_ip = inet_aton(THEIR_IP);

  data[maxlen] = '\0';

  int error;

  error = tcp_socket();

  if (!error) {
    printf("Listening on port %d...\n", OUR_PORT);
    error = tcp_listen(OUR_PORT, &their_ip);
  } else {
    printf("Socket error.\n");
  }

  if (!error){
    do {
      printf("\n\n-> Reading %d bytes...\n", maxlen);
      len = tcp_read(data, maxlen);
      printf("\n\n-> Received %d bytes of data:\n\n", len);
      printf("%s\n", data);
    } while (i++<100);
  } else {
    printf("Connect error.\n");
  }

  return error;

}

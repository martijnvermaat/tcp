#include <stdio.h>
#include <stdlib.h>
#include "tcp.h"

#define DST_IP getenv("IP2")
#define DST_PORT 80

int main(void) {
  char buf[] = "ik ben een packet";
  int len;
  int error = 0;
  int i;
  len = 17;
  
    error = tcp_socket();
    
    if (!error) {
        error = tcp_connect(inet_aton(DST_IP),DST_PORT);
    } else {
        printf("socket error");
    }
    if (!error){
      for (i=0; i<5; i++) {
        len = tcp_write(buf, len);
        printf("\n\nlen = %d\n",len);
      }
    } else {
        printf("connect error");
    }
    
    return error;
}

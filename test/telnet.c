#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "tcp.h"



int main(void) {
  char buf[100], *eth, *ip1, *ip2;
  
  ipaddr_t saddr;
  int ws, result,i;

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

  /* alarm(15); */

    /* Client process running in $IP1 */
    eth[0]='1';
    ip_init();
    
    
    if (tcp_socket()<0) return 1;
    fprintf(stdout,"Client socket() done\n");
    fflush(stdout);
    if (tcp_connect(inet_aton("192.168.2.121"),23)<0) return 1;
    fprintf(stdout,"Client connect() done\n");
    fflush(stdout); 
    
    result = tcp_read(buf,10);
    fprintf(stdout,"Client read() done (len = %d): ", result);
    if (result<0) {
        return 1;
    } else {
        for (i = 0; i < result; i++) {
            printf("%lx.",buf[i]);
        }
    }
    printf("\n");
    fflush(stdout);
    
    buf[0] = 0xff;
    buf[1] = 0xfd;
    buf[2] = 0x03;
    if (tcp_write(buf,3)<0) return 1;
    fprintf(stdout,"Client write() done\n");
    fflush(stdout);

    result = tcp_read(buf,10);
    fprintf(stdout,"Client read() done (len = %d): \n", result);
    if (result<0) {
        return 1;
    } else {
        for (i = 0; i < result; i++) {
            printf("%lx.",buf[i]);
        }
    }
    printf("\n");
    fflush(stdout);
    
    /*
    if (strcmp(client_buf,"foo")) return 1;
    fprintf(stdout,"Client response is correct\n");
    fflush(stdout);*/
    if (tcp_close()<0) return 1;
    fprintf(stdout,"Client close() done\n");
    fflush(stdout);

    result = tcp_read(buf,10);
    fprintf(stdout,"Client read() done (len = %d): \n", result);
    if (result<0) {
        return 1;
    } else {
        for (i = 0; i < result; i++) {
            printf("%lx.",buf[i]);
        }
    }
    printf("\n");
    fflush(stdout);
    return 0;
}

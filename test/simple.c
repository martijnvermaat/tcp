#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "tcp.h"



int main(void) {
  char client_buf[10000];
  char server_buf[10000], *eth, *ip1, *ip2;
  
  ipaddr_t saddr;
  int result;

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

  alarm(15);

  if (fork()) {
    /* Client process running in $IP1 */
    eth[0]='1';
    ip_init();
    
    
    if (tcp_socket()<0) return 1;
    fprintf(stdout,"Client socket() done\n");
    fflush(stdout);
    if (tcp_connect(inet_aton(ip2),80)<0) return 1;
    fprintf(stdout,"Client connect() done\n");
    fflush(stdout); 
    if (tcp_write("foo",4)<0) return 1;
    fprintf(stdout,"Client write() done\n");
    fflush(stdout);
    if (tcp_read(client_buf,10000)<0) return 1;
    fprintf(stdout,"Client read() done\n");
    fflush(stdout);
    
    if (strcmp(client_buf,"foo")) return 1;
    fprintf(stdout,"Client response is correct\n");
    fflush(stdout);
    if (tcp_close()<0) return 1;
    fprintf(stdout,"Client close() done\n");
    fflush(stdout);
    return 0;
  }
  else {
    /* Server process running in $IP2 */
    eth[0]='2';
    ip_init();
    if (tcp_socket()<0) return 1;
    fprintf(stdout,"Server socket() done\n");
    fflush(stdout);
    if (tcp_listen(80,&saddr)<0) return 1;
    fprintf(stdout,"Server listen() done\n");
    fflush(stdout);
    result = tcp_read(server_buf,16);
    fprintf(stdout,"Server read() done: %d\n",result);
    fflush(stdout);

    if (tcp_write(server_buf,strlen(server_buf)+1)<0) return 1;
    fprintf(stdout,"Server write() done\n");
    fflush(stdout);
    if (tcp_close()<0) return 1;
    fprintf(stdout,"Server close() done\n");
    fflush(stdout);
    
    
    do {
        result = tcp_read(server_buf,10);
        fprintf(stdout,"Server read() done: %d\n",result);
        fflush(stdout);
    } while (result > 0);
    return 0;
  }
}

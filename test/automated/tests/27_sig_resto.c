#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include "tcp.h"

#define BUF_SIZE 10000
/*
  Test big_test.c

  sends 10 kilobyte and check if our signal remains in tact.
*/


void print_bits(char c);
int alarm_went_of = 0;

static void alarm_handler(int sig) {
    fprintf(stderr, "test 27: alarm went of");
    fflush(stderr); 
    alarm_went_of = 1;
    /* just return to interrupt */
}

static void test_handler(int sig) {
    fprintf(stderr, "test 27: alarm went of. This test is failing.");
    fflush(stderr);  
}

int main(void) {
    
    char server_buf[BUF_SIZE], client_buf[BUF_SIZE];
    char *eth, *ip1, *ip2;

    int pid, status, total, read;
    int j, v;
    void (*oldsig1)(int);
    unsigned old_timo1;
    void (*oldsig2)(int);
    unsigned old_timo2;
    
    ipaddr_t saddr;

    eth = getenv("ETH");
    if (!eth) {
        fprintf(stderr, "The ETH environment variable must be set!\n");
        return 1;
    }

    ip1 = getenv("IP1");
    ip2 = getenv("IP2");
    if ((!ip1)||(!ip2)) {
        fprintf(stderr, "The IP1 and IP2 environment variables must be set!\n");
        return 1;
    }
    


    pid = fork();

    if (pid == -1) {
        fprintf(stderr, "Unable to fork client process\n");
        return 1;
    }

    if (pid == 0) {
            /* fill buffer with ASCII pattern 012345670123... */
        for (v=0;v<BUF_SIZE;v++) {
            client_buf[v] = (v % 8) + 48;
        }

        /* Client process running in $IP1 */
        eth[0] = '1';
 
        /*this is the alarm that should be seen at the end of the test*/
        signal(SIGALRM, test_handler);
        alarm(5);
        
        

        
        
        
        if (tcp_socket() != 0) {
            fprintf(stderr, "Client: Opening socket failed\n");
            return 1;
        }
        




        if (tcp_connect(inet_aton(ip2), 80) != 0) {
            fprintf(stderr, "Client: Connecting to server failed\n");
            return 1;
        }
        

        
        
        j = tcp_write(client_buf, BUF_SIZE);
        if (j < 1) {
            fprintf(stderr, "Client: Writing failed\n"); 
            return 1;
        }
        fprintf(stderr,"Client: Sent %d Kbytes\n",j);    
       

        
                
        if (tcp_close() != 0) {
            fprintf(stderr, "Client: Closing connection failed\n");
            return 1;
        }


        oldsig1 = signal(SIGALRM, alarm_handler);
        if ( oldsig1 != test_handler ) {
            fprintf(stderr,"Client ERROR!! old signal handler disappeared!\n");
        }
        old_timo1 = alarm(3);
        if ( old_timo1 == 0 ) {
            fprintf(stderr,"Client ERROR!! old alarm disappeared!\n");
        }


        while (tcp_read(client_buf, 4) > 0) {}

        alarm(0);

        return 0;

    } else {
    
        /*this is the alarm that should be seen at the end of the test*/
        signal(SIGALRM, test_handler);
        alarm(7);

        
        /* Server process running in $IP2 */
        eth[0]='2';

        if (tcp_socket() != 0) {
            fprintf(stderr, "Server: Opening socket failed\n");
            return 1;
        }



        if (tcp_listen(80, &saddr) < 0) {
            fprintf(stderr, "Server: Listening for client failed\n");
            return 1;
        }
        
        
        total = 0;
        fprintf(stderr,"\n\n\n\n\n\n\nserver: starting to read...\n");
        fflush(stderr);
        while (total < BUF_SIZE && !alarm_went_of) {

            read = tcp_read(&server_buf[total], BUF_SIZE - total);
            if (read < 0) {
                fprintf(stderr, "Server: Reading %d bytes failed\n",BUF_SIZE-total);
                return 1;
            } else {
                total += read;
                fprintf(stderr, "Server: Read %d bytes\n",read);
            }
        }
        fprintf(stderr, "Server: Read %d bytes in total. Closing connection...\n",total);
        
        if (tcp_close() != 0) {
            fprintf(stderr, "Server: Closing connection failed\n");
            return 1;
        }
    
        oldsig2 = signal(SIGALRM, alarm_handler);
        if ( oldsig2 != test_handler ) {
            fprintf(stderr,"Server: ERROR!! old signal handler disappeared!\n");
        }
        old_timo2 = alarm(0);
        if ( old_timo2 == 0 ) {
            fprintf(stderr,"Server: ERROR!! old alarm disappeared!\n");
        }
        
        
        for (j=0; j<total; j++) {
            if (server_buf[j] != (j % 8)+48) {
                fprintf(stderr,"ERROR!! Server read error: expected: %d, read: %d\n",(j % 8)+48,server_buf[j]);
            }
        }
        fprintf(stderr, "Server: byte check done.\n",total);



        signal(SIGALRM, alarm_handler);
        alarm(5);

        while (tcp_read(server_buf, 4) > 0) {}

        alarm(0);

        /* Wait for client process to finish */
        while (wait(&status) != pid);

        return 0;

    }
    
}



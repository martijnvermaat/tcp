#include <stdio.h>
#include <signal.h>
#include <assert.h>
#include "tcp.h"
#include "unistd.h"


#define FIN_FLAG 0x01
#define SYN_FLAG 0x02
#define RST_FLAG 0x04
#define PSH_FLAG 0x08
#define ACK_FLAG 0x10
#define URG_FLAG 0x20


/* States */
typedef enum{
    S_START, S_CLOSED, S_CONNECTING, S_LISTEN, S_SYN_SENT, S_SYN_ACK_SENT,
    S_SYN_RECEIVED, S_ESTABLISHED, S_FIN_WAIT_1, S_FIN_WAIT_2, S_CLOSE_WAIT,
    S_TIME_WAIT, S_CLOSING, S_LAST_ACK
} state_t;

/* Events */
typedef enum {
    E_SOCKET_OPEN, E_CONNECT, E_SYN_SENT, E_SYN_ACK_RECEIVED, E_LISTEN,
    E_SYN_RECEIVED, E_SYN_ACK_SENT, E_ACK_RECEIVED, E_ACK_TIME_OUT, E_CLOSE, 
    E_USER_TIME_OUT, E_FIN_RECEIVED
} event_t;

/* Prototypes */
int send_data(const char *buf, int len);
int send_syn(void);
int send_ack(void);
int send_fin(void);
int do_packet(void);
void handle_ack(tcp_u8t flags, tcp_u32t ack_nr);
void handle_data(tcp_u8t flags, tcp_u32t seq_nr, char *data, int data_size);
void handle_syn(tcp_u8t flags, tcp_u32t seq_nr, ipaddr_t their_ip);
void handle_fin(tcp_u8t flags, tcp_u32t seq_nr);
void declare_event(event_t e);
state_t get_state(void);
void clear_tcb(void);
int wait_for_ack(void);
int all_acks_received(void);
void ack_these_bytes(int bytes_delivered);

tcp_u16t tcp_checksum(ipaddr_t src, ipaddr_t dst, void *segment, int len);
void tcp_alarm(int sig);
int min(int x, int y);

void print_bits(char c);


/* TCP control block */
typedef struct tcb {
    ipaddr_t our_ipaddr;
    ipaddr_t their_ipaddr;
    tcp_u16t our_port;
    tcp_u16t their_port;
    tcp_u32t our_seq_nr;
    tcp_u32t their_seq_nr;  /* last byte we acked */
    tcp_u32t ack_nr;
    tcp_u32t expected_ack;
    char rcv_data[BUFFER_SIZE+1];  /* why +1 ? */
    int rcvd_data_start;
    int rcvd_data_size;
    int rcvd_data_psh;   /* number of bytes to push, always aligned to start of buffer */
    char *unacked_data;
    int unacked_data_len;
    state_t state;
} tcb_t;

/* Pseudo header */
typedef struct pseudo_header {
     ipaddr_t src;
     ipaddr_t dst;
     tcp_u8t zero;
     tcp_u8t ptcl;
     tcp_u16t tcp_length;
} pseudo_hdr_t;

/* TCP header without options */
typedef struct tcp_header {
    tcp_u16t src_port;
    tcp_u16t dst_port;
    tcp_u32t seq_nr;
    tcp_u32t ack_nr;
    tcp_u8t data_offset;
    tcp_u8t flags;
    tcp_u16t win_sz;
    tcp_u16t checksum;
    tcp_u16t urg_pointer;
} tcp_hdr_t;

/* TCP segment header */
typedef struct seg_header {
    pseudo_hdr_t pseudo_header;
    tcp_hdr_t tcp_header;
} seg_header_t;


typedef struct segment segment_t;

static tcb_t tcb = {
    0,       /* out_ipaddr        */
    0,       /* their_ipaddr      */
    0,       /* our_port          */
    0,       /* their_port        */
    0,       /* our_seq_nr        */
    0,       /* their_seq_nr      */
    0,       /* ack_nr            */
    0,       /* expected_ack      */
    "",      /* rcv_data          */
    0,       /* rcvd_data_start   */
    0,       /* rcvd_data_size    */
    0,       /* rcvd_data_psh     */
    "",      /* unacked_data      */
    0,       /* unacked_data_len  */
    S_START  /* state             */
};

static int alarm_went_of = 0;   /* <- in tcb? */



/* ----------------------------------- */
/*      DEBUG HELPER FUNCTIONS         */
/* ----------------------------------- */


/* Print buffer content and some info */

void print_buffer(void) {

    /*
      This function prints entire buffer space by
      using dots (.) for unused buffer space.
      Don't rewrite this function to only print
      used buffer space, as the current way might
      just be usefull for debugging.
    */

    int i;
/*    
    printf("\n\nBuffer contains %d/%d bytes starting at %d\n", tcb.rcvd_data_size, BUFFER_SIZE, tcb.rcvd_data_start);
    printf("Of this, %d bytes have to be pushed\n", tcb.rcvd_data_psh);
    printf("Buffer contains:\n\n");
    
    for (i=0; i<BUFFER_SIZE; i++) {

        if (i >= tcb.rcvd_data_start && i < tcb.rcvd_data_start + tcb.rcvd_data_size) {
            putchar(tcb.rcv_data[i]);
        } else if (tcb.rcvd_data_start + tcb.rcvd_data_size > BUFFER_SIZE
                   && i < tcb.rcvd_data_start
                   && i < tcb.rcvd_data_size - (BUFFER_SIZE - tcb.rcvd_data_start)
            ) {
            putchar(tcb.rcv_data[i]);
        } else {
            putchar('.');
        }

    }
*/
    printf("\n\n");
    fflush(stdout);

}



/* -----------TCP primitives---------- */
/*      CONNECTION ORIENTED TIER       */
/* ----------------------------------- */


/* Initiates variables        */
/* Returns 0, but -1 on error */

int tcp_socket(void) {

    /*
      Todo: this should initialize tcb and do
      nothing if called again
    */

    if (get_state() != S_START) {
        return -1;
    }

    if (!my_ipaddr){
        ip_init();
    }
    if (!my_ipaddr) {
        return -1;
    }

    declare_event(E_SOCKET_OPEN);

    tcb.our_ipaddr = my_ipaddr;

    /*
    tcb.their_seq_nr = 0;
    tcb.rcvd_data_start = 0;
    tcb.rcvd_data_size = 0;
    alarm_went_of = 0;
    */

    return 0;

}


int tcp_connect(ipaddr_t dst, int port) {

    if (get_state() != S_CLOSED) {
        return -1;
    }

    declare_event(E_CONNECT);
    tcb.our_port = CLIENT_PORT;
    tcb.their_ipaddr = dst;
    tcb.their_port = port; 

    return send_syn();

}


int tcp_listen(int port, ipaddr_t *src) {
    void (*oldsig)(int);
    unsigned oldtimo;
    
    if (get_state() != S_CLOSED) {
        return -1;
    }

    /*todo: can't we obtain the client's port dynamically? */
    tcb.their_port = CLIENT_PORT;
    tcb.our_port = port;
    
    /* reset alarm_went_of */
    alarm_went_of = 0;
    /* use our own alarm fucntion when alarm goes of */
    oldsig = signal(SIGALRM, tcp_alarm);

    declare_event(E_LISTEN);
    while (alarm_went_of == 0 && get_state() != S_ESTABLISHED) {
        do_packet();
        if (get_state() == S_SYN_RECEIVED) {
            send_syn();
            if (get_state() != S_ESTABLISHED) {
                printf("niet gelukt! laatste ack niet gekregen in 3 way HS\n");
                return -1;
            }
        }
    }
    
    if (alarm_went_of) {
        /* reset alarm_went_of and call original alarm function */
        alarm_went_of = 0;
        oldsig(SIGALRM);
        return -1;
    }
    return 0;

}


int tcp_close(void){

    if (get_state() != S_ESTABLISHED
        && get_state() != S_CLOSE_WAIT) {
        return -1;
    }

    declare_event(E_CLOSE);
    send_fin();
    return 0;
    /* todo: return error on ack time out? */
}


int tcp_read(char *buf, int maxlen) {

    int read_bytes;
    int delivered_bytes;
    void (*oldsig)(int);
    unsigned oldtimo;


    /* print_buffer();*/

    if (get_state() != S_ESTABLISHED
        && get_state() != S_FIN_WAIT_1
        && get_state() != S_FIN_WAIT_2) {
        return -1;
    }

    read_bytes = min(maxlen, BUFFER_SIZE);


    /*
      While there's no data we have to push AND there's room to read more:
      handle incomming packets
    */
    
    /* reset alarm_went_of */
    alarm_went_of = 0;
    /* use our own alarm fucntion when alarm goes of */
    oldsig = signal(SIGALRM, tcp_alarm);

    /* call do_packet while conditions are met */
    while ( alarm_went_of == 0 && 
            tcb.rcvd_data_psh == 0 && 
            tcb.rcvd_data_size < read_bytes) {
        do_packet();
    }
    
    if (alarm_went_of) {
        /* reset alarm_went_of and call original alarm function */
        alarm_went_of = 0;
        oldsig(SIGALRM);
    }

    delivered_bytes = min(maxlen, tcb.rcvd_data_size);

    /* copy first chunck */
    memcpy(buf, &tcb.rcv_data[tcb.rcvd_data_start], min(delivered_bytes, BUFFER_SIZE - tcb.rcvd_data_start));

    /* possibly copy second chunck if delivered data wraps in buffer */
    if (delivered_bytes > BUFFER_SIZE - tcb.rcvd_data_start) {
        memcpy(&buf[min(delivered_bytes, BUFFER_SIZE - tcb.rcvd_data_start)],
               tcb.rcv_data,
               delivered_bytes - (BUFFER_SIZE - tcb.rcvd_data_start));
    }

    /* adjust buffer pointers */
    tcb.rcvd_data_size -= delivered_bytes;
    tcb.rcvd_data_psh = min(tcb.rcvd_data_psh - delivered_bytes, 0);
    tcb.rcvd_data_start = (tcb.rcvd_data_start + delivered_bytes) % BUFFER_SIZE;

    printf("\n\ntcp_read: read %d bytes: %s\n\n", delivered_bytes, buf);

    /*ack_these_bytes(deliver_bytes);*/

    return delivered_bytes;

}



int tcp_write(const char *buf, int len){
    
    int bytes_sent = 0, bytes_left, data_sz;
    char *buf_pointer;
    
    bytes_left = len;
    buf_pointer = (char *) buf;

    if (get_state() != S_ESTABLISHED) {
        return -1;
    }

    while (bytes_left) {
        /*fprintf(stderr,"\n");*/
        data_sz = min(MAX_TCP_DATA, bytes_left);

        bytes_sent = send_data(buf_pointer, data_sz);
        /*fprintf(stderr,"%s: tcp_write: send_data() returned: data_sz:%d \n",inet_ntoa(my_ipaddr),bytes_sent);
        fflush(stderr);*/
        if (bytes_sent == -1) {break;}
        
        buf_pointer += bytes_sent;
        bytes_left -= bytes_sent;
        
    }
    /*fprintf(stderr,"%s: tcp_write is going to stop: bytes_left:%d \n",inet_ntoa(my_ipaddr),bytes_left);
    fflush(stderr);*/
    if (bytes_left == len) {
        /* will also happen if len=0*/
        return -1;
    } else {
        return len - bytes_left;
    }

}


/* ----------------------------------- */
/*              STATE TIER             */
/* ----------------------------------- */


int do_packet(void) {
    ipaddr_t their_ip;
    tcp_u16t src_port, dst_port, win_sz;
    tcp_u32t seq_nr, ack_nr;
    tcp_u8t flags;
    char data[MAX_TCP_DATA];
    int data_sz = 0, rcvd;

    rcvd = recv_tcp_packet(&their_ip, &src_port, &dst_port, 
                        &seq_nr, &ack_nr, &flags, &win_sz, data, &data_sz);
    if (rcvd != -1 && dst_port == tcb.our_port && src_port == tcb.their_port){

        handle_ack(flags, ack_nr);
        handle_data(flags, seq_nr, data, data_sz);
        handle_syn(flags, seq_nr, their_ip);
        handle_fin(flags, seq_nr);
    }
    
    return rcvd;
}


void handle_ack(tcp_u8t flags, tcp_u32t ack_nr) {

    if (!(ACK_FLAG & flags)){
        return;
    }
     printf("\n%s: incoming ack: %lu \n",inet_ntoa(my_ipaddr),ack_nr);
     printf("%s: expected ack: %lu\n", inet_ntoa(my_ipaddr),tcb.expected_ack);
     fflush(stdout);
    if (ack_nr == tcb.expected_ack) {

        tcb.our_seq_nr = ack_nr;
        tcb.unacked_data_len = 0;

        if (get_state() == S_ESTABLISHED) {return;}

        if (get_state() == S_SYN_ACK_SENT) {

            declare_event(E_ACK_RECEIVED);

        } else if (get_state() == S_FIN_WAIT_1) {

            declare_event(E_ACK_RECEIVED);

        } else if (get_state() == S_LAST_ACK) {

            declare_event(E_ACK_RECEIVED);

        } else if (get_state() == S_CLOSING) {

            declare_event(E_ACK_RECEIVED);
        }
    }
}



void handle_data(tcp_u8t flags, tcp_u32t seq_nr, char *data, int data_size) {

    int fresh_data_start, fresh_data_size, 
        size, first_size, free_buffer_space;

    if (data_size > 0 && tcb.rcvd_data_size < BUFFER_SIZE) {

        /* okay, we are able to store data */

        printf("handle data (size %d)\n", data_size);
        printf("incoming sequence number: %lx\n", seq_nr);
        printf("their current sequence number: %lx\n", tcb.their_seq_nr);

        /* start byte of data that's new for us */
        fresh_data_start = tcb.their_seq_nr - seq_nr;  /* shouldn't their_seq_nr be ack_nr? */
        fresh_data_size = data_size - fresh_data_start;

        if (fresh_data_size > 0  && tcb.their_seq_nr >= seq_nr) {

            /* it is what we expect;
               - at least 1 byte we don't have yet
               - and directly following the bytes we do have */

            printf("Incomming data: %d bytes\n", data_size);
            fflush(stdout);

            /* number of bytes we can accept */
            free_buffer_space = BUFFER_SIZE - tcb.rcvd_data_size;
            size = min(free_buffer_space, fresh_data_size);

            printf("We use %d bytes of it starting at %d\n", size, fresh_data_start);

            /* now copy the data to our (circular) buffer */

            if (tcb.rcvd_data_start + tcb.rcvd_data_size >= BUFFER_SIZE) {

                /* copy data to buffer in one chunck */

                printf("Buffer already wrapped, copying %d bytes to buffer\n", size);

                memcpy(&tcb.rcv_data[tcb.rcvd_data_start + tcb.rcvd_data_size - BUFFER_SIZE], &data[fresh_data_start], size);

            } else {

                /* copy data to buffer and wrap at end of buffer if needed */

                first_size = min(size, BUFFER_SIZE - (tcb.rcvd_data_start + tcb.rcvd_data_size));

                printf("Copying first chunk of %d bytes\n", first_size);

                memcpy(&tcb.rcv_data[tcb.rcvd_data_start + tcb.rcvd_data_size], &data[fresh_data_start], first_size);

                if (first_size < size) {

                    /* second chunck */

                    printf("Copying second chunck of %d bytes\n", size - first_size);

                    memcpy(tcb.rcv_data, &data[fresh_data_start + first_size], size - first_size);

                }

            }

            tcb.rcvd_data_size += size;
            tcb.their_seq_nr += size;

            if (PSH_FLAG & flags) {
                tcb.rcvd_data_psh = tcb.rcvd_data_size;
            }

            printf("\n%s: handle_data: size: %d",inet_ntoa(my_ipaddr),size);
            printf("\n%s: handle_data: rcvd_data_size: %u",inet_ntoa(my_ipaddr),tcb.rcvd_data_size);

            ack_these_bytes(size);

  printf("\n\n");
  print_buffer();
  printf("\n\n");


        }

    }

    /* data should always fit in buffer */
    assert(tcb.rcvd_data_size <= BUFFER_SIZE);

}


void handle_syn(tcp_u8t flags, tcp_u32t seq_nr, ipaddr_t their_ip) {

    if (!(SYN_FLAG & flags)){
        return;
    }
    printf("\n%s syn received\n",inet_ntoa(my_ipaddr)); 
    fflush(stdout);

    if (get_state() == S_LISTEN) {
        tcb.their_ipaddr = their_ip;
        printf(" from %s\n",inet_ntoa(their_ip));
        fflush(stdout);
        tcb.their_seq_nr = seq_nr + 1;
        tcb.ack_nr = seq_nr + 1;
    
        declare_event(E_SYN_RECEIVED);
        
        /* send_syn will be called in tcp_listen */


    } else if (get_state() == S_SYN_SENT) {

        if (all_acks_received()) {
            fflush(stdout);
            declare_event(E_SYN_ACK_RECEIVED);
            /* todo: received sequence number may be invalid */
            tcb.their_seq_nr = seq_nr + 1;
            tcb.ack_nr = seq_nr + 1;
            send_ack();
        }
        
    }
}


void handle_fin(tcp_u8t flags, tcp_u32t seq_nr) {
    int s;
    if (FIN_FLAG & flags) {
        s = get_state();
        printf("\n%s: fin received\n",inet_ntoa(my_ipaddr));
        fflush(stdout);
        if (s == S_ESTABLISHED || s == S_FIN_WAIT_1 || s == S_FIN_WAIT_2) {
            printf("%s: fin accepted\n",inet_ntoa(my_ipaddr));
            fflush(stdout);
            declare_event(E_FIN_RECEIVED);
            /* todo: received sequence number may be invalid */
            tcb.their_seq_nr = seq_nr + 1;
            tcb.ack_nr = seq_nr + 1;
            send_ack();
        }
    }
}



/*
  buf       Buffer with bytes to send
  len       Number of bytes to send

  Returns number of bytes sent, or -1 on error.
*/

int send_data(const char *buf, int len) {
    
    int bytes_sent = 0;
    char flags = PSH_FLAG | ACK_FLAG;
    int retransmission_allowed = MAX_RETRANSMISSION;
    /*fprintf(stderr, "%s: send_data starts\n",inet_ntoa(my_ipaddr));
    fflush(stderr);*/
    while (retransmission_allowed--) {
        bytes_sent = send_tcp_packet(tcb.their_ipaddr, tcb.our_port, 
            tcb.their_port, tcb.our_seq_nr, tcb.ack_nr, flags, 1, buf, len);
        
        /* todo: misschien moeten we dit er maar uit laten.

          Redenen voor send_tcp_packet om -1 terug te geven:
          * ip_init failed (kon eigen ip adres niet vaststellen)
          * doel is op ander netwerk en er is geen gateway gevonden
          * ethernet adres van doel kon niet vastgesteld worden
          * eth_send failed

          Dus eigenlijk kan het er wel in blijven, want de kans is niet
          groot dat het de volgende loop iteratie wel lukt...
        */

        if(bytes_sent == -1){
            fprintf(stderr,"no bytes sent");
            fflush(stderr);
            return -1;
        } else {
            fprintf(stderr,"%s: %d bytes sent (seq %lu)\n", inet_ntoa(my_ipaddr), bytes_sent, tcb.our_seq_nr);
            fflush(stderr);
            tcb.expected_ack = tcb.our_seq_nr + bytes_sent;
            tcb.unacked_data_len = bytes_sent;
        }
                           
        if (wait_for_ack()){
            /*tcb.our_seq_nr += bytes_sent;*/
            return bytes_sent;
        } 
    }
    return -1;
}


/*
    Sends a syn packet, and waits for ack.
    Returns 0, but -1 on error.
*/

int send_syn(void) {
    
    char *buf;
    char flags = PSH_FLAG | SYN_FLAG;
    int retransmission_allowed = MAX_RETRANSMISSION;
    int result;

    if (get_state() != S_CONNECTING) {
        flags |= ACK_FLAG;
    }

    while (retransmission_allowed--) {
    
        /* send syn packet */
        result = send_tcp_packet(tcb.their_ipaddr, tcb.our_port, 
            tcb.their_port, tcb.our_seq_nr, tcb.ack_nr, flags, 1, buf, 0);
        
        /* check result */
        if(result == -1){
            return -1;
        } else {
            printf("\n %s sent syn packet, seq %lu\n",inet_ntoa(my_ipaddr),tcb.our_seq_nr); 
            tcb.expected_ack = tcb.our_seq_nr + 1;
            if (flags & ACK_FLAG) {
                declare_event(E_SYN_ACK_SENT);
            } else {
                declare_event(E_SYN_SENT);
            }
        }
        
        /* wait for ack */          
        if (wait_for_ack() && get_state() == S_ESTABLISHED){
            /* todo: increase seq_nr on retransmission? */
            /*tcb.our_seq_nr += 1;*/
            return 0;
        } else {
            declare_event(E_ACK_TIME_OUT);
        }
    }
    return -1;
}



/*
    Sends a fin packet, and waits for ack.
    Returns 0, but -1 on error.
*/

int send_fin(void) {
    
    char *buf;
    char flags = PSH_FLAG | FIN_FLAG | ACK_FLAG;
    int retransmission_allowed = MAX_RETRANSMISSION;
    int result;

    while (retransmission_allowed--) {
    
        /* send fin packet */
        result = send_tcp_packet(tcb.their_ipaddr, tcb.our_port, 
            tcb.their_port, tcb.our_seq_nr, tcb.ack_nr, flags, 1, buf, 0);
        
        /* check result */
        if(result == -1){
            return -1;
        } else {
            fprintf(stdout,"\n %s sent fin packet, seq %lu\n",inet_ntoa(my_ipaddr),tcb.our_seq_nr); 
            tcb.expected_ack = tcb.our_seq_nr + 1;
        }
        
        /* wait for ack */          
        if (wait_for_ack() && get_state() != S_FIN_WAIT_1){
            return 0;
        }
    }
    declare_event(E_USER_TIME_OUT);
    return -1;
}


/*
    Sends an ack packet.
    Returns 0, but -1 on error.
*/

int send_ack(void) {

    char *buf;
    char flags = PSH_FLAG | ACK_FLAG;

    flags |= PSH_FLAG;
    flags |= ACK_FLAG;

    printf("%s sending ack\n",inet_ntoa(my_ipaddr));
    return send_tcp_packet(tcb.their_ipaddr, tcb.our_port, 
            tcb.their_port, tcb.our_seq_nr, tcb.ack_nr, flags, 1, buf, 0);
}



int wait_for_ack(void){

    void (*oldsig)(int);
    unsigned oldtimo;

    alarm_went_of = 0;
    oldsig = signal(SIGALRM, tcp_alarm);
    oldtimo = alarm(RTT);
    
    while (alarm_went_of == 0 && !all_acks_received()) {
        do_packet();
    }

    signal(SIGALRM, oldsig);    
    alarm(oldtimo);
    alarm_went_of = 0;
    
    return all_acks_received();
}


void ack_these_bytes(int bytes_delivered) {

    printf("             %s acknr: %lx\n",inet_ntoa(my_ipaddr),tcb.ack_nr);
    tcb.ack_nr += bytes_delivered;
    printf("             %s acknr: %lx\n",inet_ntoa(my_ipaddr),tcb.ack_nr);
    send_ack();
    printf("%s acked %d bytes\n",inet_ntoa(my_ipaddr),bytes_delivered);
    fflush(stdout);

}


void clear_tcb(void) {
    tcb.state = S_CLOSED;
    tcb.our_ipaddr = my_ipaddr;
    tcb.their_seq_nr = 0;
    tcb.their_ipaddr = 0;
    tcb.their_port = 0;
    tcb.rcvd_data_start = 0;
    tcb.rcvd_data_size = 0;
    tcb.unacked_data_len = 0;
}




void tcp_alarm(int sig){
    alarm_went_of = 1;
    fprintf(stderr,"%s: tcp_alarm went of\n",inet_ntoa(my_ipaddr));
    fflush(stderr);
}


/* performs state transition based on event and current state */
void declare_event(event_t e) {
    int error = 0;
    int s;
    
    s = tcb.state;

    if (s == S_START && e == E_SOCKET_OPEN) {
        tcb.state = S_CLOSED;
        printf("%s: Event: E_SOCKET_OPEN, State to S_CLOSED\n",inet_ntoa(my_ipaddr));
        fflush(stdout);

    } else if (s == S_CLOSED && e == E_CONNECT) {
        tcb.state = S_CONNECTING;
        printf("%s: Event: E_CONNECT, State to S_CONNECTING\n",inet_ntoa(my_ipaddr));
        fflush(stdout);
        
    } else if (s == S_CLOSED && e == E_LISTEN) {
        tcb.state = S_LISTEN;
        printf("%s: Event: E_LISTEN, State to S_LISTEN\n",inet_ntoa(my_ipaddr));
        fflush(stdout);

    } else if (s == S_CONNECTING && e == E_SYN_SENT) {
        tcb.state = S_SYN_SENT;
        printf("%s: Event: E_SYN_SENT, State to S_SYN_SENT\n",inet_ntoa(my_ipaddr));
        fflush(stdout);
        
    } else if (s == S_SYN_SENT && e == E_SYN_ACK_RECEIVED) {
        tcb.state = S_ESTABLISHED;
        printf("%s: Event: E_SYN_ACK_RECEIVED, State to S_ESTABLISHED\n",inet_ntoa(my_ipaddr));
        fflush(stdout);
        
    } else if (s == S_LISTEN && e == E_SYN_RECEIVED) {
        tcb.state = S_SYN_RECEIVED;
        printf("%s: Event: E_SYN_RECEIVED, State to S_SYN_RECEIVED\n",inet_ntoa(my_ipaddr));
        fflush(stdout);
        
    } else if (s == S_SYN_RECEIVED && e == E_SYN_ACK_SENT) {
        tcb.state = S_SYN_ACK_SENT;
        printf("%s: Event: E_SYN_ACK_SENT, State to S_SYN_ACK_SENT\n",inet_ntoa(my_ipaddr));
        fflush(stdout);
        
    } else if (s == S_SYN_ACK_SENT && e == E_ACK_RECEIVED) {
        tcb.state = S_ESTABLISHED;
        printf("%s: Event: E_ACK_RECEIVED, State to S_ESTABLISHED\n",inet_ntoa(my_ipaddr));
        fflush(stdout);
        
    } else if (s == S_ESTABLISHED && e == E_CLOSE) {
        tcb.state = S_FIN_WAIT_1;
        printf("%s: Event: E_CLOSE, State to S_FIN_WAIT_1\n",inet_ntoa(my_ipaddr));
        fflush(stdout);
          
    } else if (s == S_FIN_WAIT_1 && e == E_FIN_RECEIVED) {
        tcb.state = S_CLOSING;
        printf("%s: Event: E_FIN_RECEIVED, State to S_CLOSING\n",inet_ntoa(my_ipaddr));
        fflush(stdout);
        
    } else if (s == S_FIN_WAIT_1 && e == E_ACK_RECEIVED) {
        tcb.state = S_FIN_WAIT_2;
        printf("%s: Event: E_ACK_RECEIVED, State to S_FIN_WAIT_2\n",inet_ntoa(my_ipaddr));
        fflush(stdout);
  
    } else if (s == S_FIN_WAIT_2 && e == E_FIN_RECEIVED) {
        tcb.state = S_TIME_WAIT;
        printf("%s: Event: E_FIN_RECEIVED, State to S_TIME_WAIT\n",inet_ntoa(my_ipaddr));
        fflush(stdout);
        
    } else if (s == S_ESTABLISHED && e == E_FIN_RECEIVED) {
        tcb.state = S_CLOSE_WAIT;    
        printf("%s: Event: E_FIN_RECEIVED, State to S_CLOSE_WAIT\n",inet_ntoa(my_ipaddr));
        fflush(stdout);
        
    } else if (s == S_CLOSING && e == E_ACK_RECEIVED) {
        tcb.state = S_TIME_WAIT;
        printf("%s: Event: E_ACK_RECEIVED, State to S_TIME_WAIT\n",inet_ntoa(my_ipaddr));
        fflush(stdout);
    
    } else if (s == S_CLOSE_WAIT && e == E_CLOSE) {
        tcb.state = S_LAST_ACK;
        printf("%s: Event: E_CLOSE, State to S_LAST_ACK\n",inet_ntoa(my_ipaddr));
        fflush(stdout);
        
    } else if (s == S_LAST_ACK && e == E_ACK_RECEIVED) {
        tcb.state = S_CLOSED;
        printf("%s: Event: E_ACK_RECEIVED, State to S_CLOSED\n",inet_ntoa(my_ipaddr));
        fflush(stdout);
        
    } else if (e == E_USER_TIME_OUT) {
        tcb.state = S_CLOSED;
        clear_tcb();
        printf("%s: Event: E_USER_TIME_OUT, State to S_CLOSED\n",inet_ntoa(my_ipaddr));
        fflush(stdout);
        
    } else {
        error = 1;
    }
    
#ifdef DEBUG
    if (error) {
        printf("\n %s: UNSUPPORTED TRANSITION!\n", inet_ntoa(my_ipaddr));
        printf("current state: %d, event: %d\n",s,e);
    }
#endif
}



state_t get_state(void){
    return tcb.state;
}


int all_acks_received(void) { 
    return tcb.our_seq_nr == tcb.expected_ack;
}

/* ----------------------------------- */
/*         CONNECTIONLESS TIER         */
/* ----------------------------------- */

int send_tcp_packet(ipaddr_t dst, 
        tcp_u16t src_port,
        tcp_u16t dst_port, 
        tcp_u32t seq_nr, 
        tcp_u32t ack_nr, 
        tcp_u8t flags, 
        tcp_u16t win_sz, 
        const char *data, 
        int data_sz) {
    
    int bytes_sent;
    tcp_u32t tcp_sz, hdr_sz;
    tcp_hdr_t *tcp;
	
    char segment[MAX_TCP_SEGMENT_LEN];

    /*fprintf(stderr, "%s: send_tcp_packet starts:\n",inet_ntoa(my_ipaddr));
    fflush(stderr);*/
    hdr_sz = sizeof(tcp_hdr_t);
    tcp_sz = hdr_sz + data_sz;
    
    tcp = (tcp_hdr_t *) segment;

    tcp->src_port = htons(src_port);
    tcp->dst_port = htons(dst_port);
    tcp->seq_nr = htonl(seq_nr);
    tcp->ack_nr = htonl(ack_nr);
    tcp->data_offset = (hdr_sz >> 2) << 4;
    tcp->flags = flags;
    tcp->win_sz = htons(win_sz);
    tcp->checksum = 0x00;
    tcp->urg_pointer = 0;

    memcpy(&segment[hdr_sz], data, data_sz);
    
    printf("\n || == %s is sending segment ==\n",inet_ntoa(my_ipaddr));
    printf(" || seq_nr %lx\n",tcp->seq_nr);
    printf(" || ack_nr %lx\n",tcp->ack_nr);
    printf(" || checksum %x\n\n",tcp->checksum);
       
    tcp->checksum = tcp_checksum(my_ipaddr, dst, tcp, tcp_sz);
    tcp->checksum = tcp_checksum(my_ipaddr, dst, tcp, tcp_sz);
    if (tcp->checksum != 0) { 
        fprintf(stderr,"%s: checksum error: 0x%x\n", inet_ntoa(my_ipaddr),tcp->checksum );
    }
    tcp->checksum = tcp_checksum(my_ipaddr, dst, tcp, tcp_sz);


    /*    fprintf(stderr, "%s: sending over ip: %d\n",inet_ntoa(my_ipaddr),tcp_sz);
    fflush(stderr);*/
    bytes_sent = ip_send(dst,IP_PROTO_TCP, 2, tcp, tcp_sz );
    /*fprintf(stderr, "%s: bytes sent: %d\n",inet_ntoa(my_ipaddr),bytes_sent);
    fflush(stderr);*/
    assert(bytes_sent == tcp_sz);
    if (bytes_sent == -1){
        return -1;
    } else {
        return bytes_sent - hdr_sz;
    }
}


int recv_tcp_packet(ipaddr_t *src_ip, 
        tcp_u16t *src_port,
        tcp_u16t *dst_port, 
        tcp_u32t *seq_nr, 
        tcp_u32t *ack_nr, 
        tcp_u8t *flags,
        tcp_u16t *win_sz, 
        char *data, 
        int *data_sz) {
    
    int len = 0;
    tcp_hdr_t *tcp;
    ipaddr_t dst_ip;
    tcp_u16t proto = 0, id, chksm = 1;
    char *segment;
    tcp_u8t hdr_sz;
    

    while (chksm){
        proto = 0;
        while (proto != IP_PROTO_TCP) {
            len = ip_receive(src_ip, &dst_ip, &proto, &id, &segment);
            
            if (len == -1){
                return -1;
            }
        }
        tcp = (tcp_hdr_t *) segment;
        
        /* todo: connectionless tier should not touch the tcb, but 
           can we believe ip? */
        
        chksm = tcp_checksum(*src_ip, tcb.our_ipaddr, tcp, len);
    }
               
    /* todo: what is the function of the ID field???*/

    *src_port = ntohs(tcp->src_port);
    *dst_port = ntohs(tcp->dst_port);
    *seq_nr   = ntohl(tcp->seq_nr);
    *ack_nr   = ntohl(tcp->ack_nr);
    *flags    = tcp->flags;
    *win_sz   = ntohs(tcp->win_sz);
        
    hdr_sz = (tcp->data_offset) >> 2;
    *data_sz = len - (int)hdr_sz;
    
    memcpy(data, &segment[(int)hdr_sz], *data_sz);
    free(segment);
    return *data_sz;

}


 /*
 * 16-bit one complement check sum over segment and pseudo header
 */
 
tcp_u16t tcp_checksum(ipaddr_t src, ipaddr_t dst, void *segment, int len) {
    
    unsigned short *sp;
    unsigned long sum, oneword = 0x00010000;
    int count; 

    /*assemble pseudoheader*/
    pseudo_hdr_t pseudo_hdr;
    /*fprintf(stderr, "%s: tcp_checksum starts\n",inet_ntoa(my_ipaddr));
    fflush(stderr);*/
    pseudo_hdr.src = (src);
    pseudo_hdr.dst = (dst);
    pseudo_hdr.zero = 0;
    pseudo_hdr.ptcl = IP_PROTO_TCP;
    pseudo_hdr.tcp_length = htons(len);
    
                
    /* calculate sum of one complements over pseudo header*/
    count = sizeof(pseudo_hdr_t) >> 1;
    
    for (sum = 0, sp = (unsigned short *)&pseudo_hdr; count--; ) {
        sum += *sp++;
        if (sum >= oneword) { /* wrap carry into low bit */
            sum -= oneword;
            sum++;
        }
    }

    /*fprintf(stderr, "%s: checksum: peudo header calculated\n",inet_ntoa(my_ipaddr));
    fflush(stderr);*/

    /* add sum of one complements over segment */
    count = len >> 1;    
    for (sp = (unsigned short *)segment; count--; ) {
        sum += *sp++;
        if (sum >= oneword) { /* wrap carry into low bit */
            sum -= oneword;
            sum++;
        }
    }
    
    /*fprintf(stderr, "%s checksum: header + data calculated\n",inet_ntoa(my_ipaddr));
    fflush(stderr);*/
        
    
    /* possibly add the last byte */
    if (len & 1) {
#ifdef LITTLE_ENDIAN
        sum += ( (unsigned short) *((char *) sp) ) &  0x00ff; 
#else
        sum += ((unsigned short) *((char *) sp)) << 8;
#endif
        if (sum >= oneword) { /* wrap carry into low bit */
            sum -= oneword;
            sum++;
        }
    }
    return ~sum;
}


int min(int x, int y) {
    return ((x) < (y) ? (x) : (y));
}

void print_bits(char c) {
    char byte;
    void *output;
    byte = 0x80;
    output = stdout;
    if (byte & c) {
        fprintf(output, "1");
    } else {
        fprintf(output, "0");
    }
    byte = 0x40;
    if (byte & c) {
        fprintf(output, "1");
    } else {
        fprintf(output, "0");
    }
    byte = 0x20;
    if (byte & c) {
        fprintf(output, "1");
    } else {
        fprintf(output, "0");
    }
    byte = 0x10;
    if (byte & c) {
        fprintf(output, "1");
    } else {
        fprintf(output, "0");
    }
    byte = 0x08;
    fprintf(output,".");
    if (byte & c) {
        fprintf(output, "1");
    } else {
        fprintf(output, "0");
    }
    byte = 0x04;
    if (byte & c) {
        fprintf(output, "1");
    } else {
        fprintf(output, "0");
    }
    byte = 0x02;
    if (byte & c) {
        fprintf(output, "1");
    } else {
        fprintf(output, "0");
    }
    byte = 0x01;
    if (byte & c) {
        fprintf(output, "1");
    } else {
        fprintf(output, "0");
    }
}

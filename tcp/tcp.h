#ifndef __TCP_H__
#define __TCP_H__

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <alloca.h>
#include "inet.h"
#include "ip.h"


#define MAX_IP_PACKET_LEN 8192
#define IP_HEADER_LEN 20
#define TCP_PSEUDO_HDR 12
#define TCP_HDR 20
#define MAX_TCP_SEGMENT_LEN (MAX_IP_PACKET_LEN - IP_HEADER_LEN)
#define MAX_TCP_DATA (MAX_TCP_SEGMENT_LEN - TCP_HDR)
#define MAX_RETRANSMISSION 5
#define BUFFER_SIZE 64000

#define RTT 1   /* in seconds */

#define	IP_PROTO_TCP	6
#define CLIENT_PORT     8042	

typedef unsigned char tcp_u8t;   /* <- when doing arithmetic we should cast to int */
typedef unsigned short tcp_u16t;
typedef unsigned long tcp_u32t;

int tcp_socket(void);
int tcp_connect(ipaddr_t dst, int port);
int tcp_listen(int port, ipaddr_t *src);
int tcp_close(void);
int tcp_write(const char *buf, int len);
int tcp_read(char *buf, int maxlen);

int send_tcp_packet(ipaddr_t dst, 
        tcp_u16t src_port,
        tcp_u16t dst_port, 
        tcp_u32t seq_nr, 
        tcp_u32t  ack_nr, 
        tcp_u8t flags, 
        tcp_u16t win_sz, 
        const char *data, 
        int data_sz);

int recv_tcp_packet(ipaddr_t *src, 
        tcp_u16t *src_port,
        tcp_u16t *dst_port, 
        tcp_u32t *seq_nr, 
        tcp_u32t *ack_nr, 
        tcp_u8t *flags,
        tcp_u16t *win_z, 
        char *data, 
        int *data_sz);


#endif /* __TCP_H__ */

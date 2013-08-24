#ifndef _CLIENT_H_
#define _CLIENT_H_

#include <libnet.h>
#include <pthread.h>
#include <pcap.h>
#include "common.h"

#define WIN_SIZE 16
#define TIMEOUT_MS 2000

typedef struct message_s {
    u_long seq;
    char* msg;
    int msg_s;
    struct message_s* next;
} message_t;

typedef struct client_s {
    pcap_t* pcap;
    libnet_t* lnet;
    libnet_ptag_t udp_ptag;
    libnet_ptag_t ipv4_ptag;
    libnet_ptag_t eth_ptag;
    pthread_t thread;
    u_char terminate;
    u_char src_mac[MAC_LEN];
    u_char dst_mac[MAC_LEN];
    u_char priority;
    u_long src_ip, dst_ip;
    u_short src_port, dst_port;
    u_long seq;
    u_long ack;
    pthread_mutex_t* lock;
    pthread_cond_t* has_msg;
    message_t* head;
    message_t* tail;
} client_t;

client_t* client_init(char* dev, u_short port, u_char pri);
int client_send(client_t* clt, char* msg, int len);
void client_close(client_t* clt);
void* client_loop(void* client_ptr);
int client_init_fields(client_t* clt);
int client_build_packet(client_t* clt, char* payload, int payload_s, u_long seq, u_char flags);
u_char client_extract_priority(char* msg, int len);
void client_free_messages(client_t* client);
u_long client_parse_ack(const u_char* data);

#endif

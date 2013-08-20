#ifndef _SERVER_H_
#define _SERVER_H_

#include <pcap.h>
#include <libnet.h>
#include "common.h"

#define SOURCE_NUM_MAX 1024
#define SEQ_OFFSET 4
#define SRC_PORT_OFFSET 0
#define SRC_IP_OFFSET 12
#define SRC_MAC_OFFSET 6

typedef struct packet_s {
    u_long seq;
    u_char* data;
    int len;
    struct packet_s* next;
} packet_t;

typedef struct source_s {
    u_long ip;
    u_short port;
    u_char mac[MAC_LEN];
    u_long seq;
    packet_t* packets;
} source_t;

#endif

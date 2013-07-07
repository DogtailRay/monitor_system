#ifndef LOG_RECEIVER_H
#define LOG_RECEIVER_H

#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/md5.h>

#define MAC_LEN 6
#define ETH_HLEN 14
#define IP_HLEN 20
#define TCP_HLEN 20
#define TCP_IP_HLEN 40
#define DATA_MAX_LEN 1500
#define PRI_OFFSET 20
#define IDX_OFFSET 1
#define LEN_OFFSET 2
#define MD5_OFFSET 4
#define PAYLOAD_OFFSET TCP_IP_HLEN

#define MAX_PENDING_LEN 1024

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;

struct pending_message_s;
typedef struct pending_message_s pmsg_t;
struct pending_message_s
{
    u_char idx;
    u_short len;
    u_char priority;
    u_char md5[16];
    u_int c_len;
    char content[DATA_MAX_LEN];
    pmsg_t* next;
};

typedef struct log_receiver_s
{
    pcap_t *pcap;
    char* logfile;
    int pending_length;
    pmsg_t* pending_list[MAX_PENDING_LEN];
} lrecv_t;

lrecv_t* log_receiver_init(const char* dev, const char* logfile);
void log_receiver_close(lrecv_t* l);
void log_receiver_loop(lrecv_t* l, int cnt);
void log_receiver_parse_packet(u_char* l, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void log_receiver_pend_msg(lrecv_t* l, pmsg_t* msg);
void log_receiver_log_msg(lrecv_t* l, pmsg_t* msg);
int log_receiver_cmp_md5(const u_char* a, const u_char* b);
pmsg_t* log_receiver_insert_msg(pmsg_t* head, pmsg_t* msg);
int log_receiver_msg_complete(pmsg_t* msg);

#endif

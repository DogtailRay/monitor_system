#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <time.h>

#include "client.h"

void* client_loop(void* client_ptr)
{
    client_t* client = (client_t*) client_ptr;
    if (client_init_fields(client) != 0) {
        fprintf(stderr, "Fields initialization failed!");
        return (void *)1;
    }

    message_t* current = NULL;
    u_char first = 1;

    while (1) {
        printf("enter while\n");
        pthread_mutex_lock(client->lock);
        printf("thread get lock!\n");
        while (client->head == NULL) {
            if (client->terminate) {
                pthread_mutex_unlock(client->lock);
                return 0;
            }
            printf("sleep\n");
            pthread_cond_wait(client->has_msg, client->lock);
            printf("wake up\n");
            current = client->head;
        }
        printf("after first while\n");
        while (current != NULL && current->seq < client->ack + WIN_SIZE) {
            u_char flags = TH_PUSH;
            if (first) {
                flags = TH_PUSH | TH_SYN;
                first = 0;
            }
            client_build_packet(client, current->msg, current->msg_s,
                                current->seq, flags);
            printf("before write\n");
            libnet_write(client->lnet);
            printf("after write\n");
            current = current->next;
        }
        pthread_mutex_unlock(client->lock);

        struct pcap_pkthdr* pkthdr;
        const u_char* pkt_data;
        int rval = pcap_next_ex(client->pcap, &pkthdr, &pkt_data);
        switch (rval) {
            case 1:
                if (pkthdr->caplen == pkthdr->len) {
                    client->ack = client_parse_ack(pkt_data);
                    client_free_messages(client);
                }
                free(pkthdr);
                free((void *)pkt_data);
                break;
            case 0:
                current = client->head;
                break;
            default:
                pcap_perror(client->pcap, "pcap_next_ex error");
                break;
        }
    }
    return 0;
}

void client_free_messages(client_t* client)
{
    pthread_mutex_lock(client->lock);
    message_t* current = client->head;
    while (current != NULL && current->seq < client->ack)
    {
        client->head = current->next;
        free(current);
        current = client->head;
    }
    if (client->head == NULL) {
        client->tail = NULL;
    }
    pthread_mutex_unlock(client->lock);
}

u_long client_parse_ack(const u_char* data)
{
    int offset = LIBNET_ETH_H + LIBNET_IPV4_H + ACK_OFFSET;
    return 0;
}

int client_send(client_t* clt, char* msg, int len)
{
    pthread_mutex_lock(clt->lock);
    printf("send get lock\n");

    message_t* new_msg = malloc(sizeof(message_t));
    new_msg->seq = clt->seq;
    clt->seq += 1;
    new_msg->msg = malloc(len);
    memcpy(new_msg->msg, msg, len);
    new_msg->msg_s = len;
    new_msg->next = NULL;
    if (clt->tail == NULL) {
        clt->head = new_msg;
        clt->tail = new_msg;
    } else {
        clt->tail->next = new_msg;
        clt->tail = new_msg;
    }

    pthread_mutex_unlock(clt->lock);
    printf("send release lock\n");
    pthread_cond_signal(clt->has_msg);
}

u_char client_extract_priority(char* msg, int len)
{
    u_char pri = 0;
    int i = 0;
    while (i < len && msg[i] != '<') {
        ++i;
    }
    ++i;
    while (i < len && msg[i] != '>') {
        pri = pri * 10 + msg[i] - '0';
        ++i;
    }
    return pri;
}

int client_init_fields(client_t* clt)
{
    /* Get source MAC */
    struct libnet_ether_addr* src_hwaddr = libnet_get_hwaddr(clt->lnet);
    if (src_hwaddr == NULL) {
        perror(libnet_geterror(clt->lnet));
        return 1;
    }
    memcpy(clt->src_mac, src_hwaddr->ether_addr_octet, MAC_LEN);
    /* Set destination MAC */
    memset(clt->dst_mac, 0x11, MAC_LEN);
    clt->dst_mac[MAC_LEN-1] = clt->priority;

    /* Get source IP */
    clt->src_ip = libnet_get_ipaddr4(clt->lnet);
    if (clt->src_ip == 0) {
        perror(libnet_geterror(clt->lnet));
        return 1;
    }
    /* Set destination IP */
    struct in_addr* inp = malloc(sizeof(struct in_addr));
    if (inet_aton(LOG_IP, inp) == 0) {
        perror("destination ip error");
        return 1;
    }
    memcpy(&(clt->dst_ip), &(inp->s_addr), sizeof(u_long));
    free(inp);

    /* Set destination port */
    clt->dst_port = LOG_PORT;

    clt->tcp_ptag = 0;
    clt->ipv4_ptag = 0;
    clt->eth_ptag = 0;

    return 0;
}

int client_build_packet(client_t* clt, char* payload, int payload_s, u_long seq, u_char flags)
{
    /* Build TCP header */
    clt->tcp_ptag = libnet_build_tcp(
            clt->src_port, /* source port */
            clt->dst_port, /* destination port */
            seq, /* sequence number */
            0x01010101, /* acknowledgement num */
            flags, /* control flags */
            1, /* window size */
            0, /* checksum */
            0, /* urgent pointer */
            LIBNET_TCP_H + payload_s, /* TCP packet size */
            (uint8_t*)payload, /* payload */
            payload_s, /* payload size */
            clt->lnet, /* libnet handle */
            clt->tcp_ptag); /* libnet id */
    if (clt->tcp_ptag == -1)
    {
        fprintf(stderr, "Can't build TCP header: %s\n", libnet_geterror(clt->lnet));
        return 1;
    }

    /* Build ipv4 header */
    clt->ipv4_ptag = libnet_build_ipv4(
            LIBNET_IPV4_H + LIBNET_TCP_H + payload_s,/* length */
            0, /* TOS */
            242, /* IP ID */
            0, /* IP Frag */
            64, /* TTL */
            IPPROTO_TCP, /* protocol */
            0, /* checksum */
            clt->src_ip, /* source IP */
            clt->dst_ip, /* destination IP */
            NULL, /* payload */
            0, /* payload size */
            clt->lnet, /* libnet handle */
            clt->ipv4_ptag); /* libnet id */
    if (clt->ipv4_ptag == -1)
    {
        fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(clt->lnet));
        return 1;
    }

    clt->eth_ptag = libnet_build_ethernet(
            clt->dst_mac, /* ethernet destination */
            clt->src_mac, /* ethernet source */
            ETHERTYPE_IP, /* protocol type */
            NULL, /* payload */
            0, /* payload size */
            clt->lnet, /* libnet handle */
            clt->eth_ptag); /* libnet id */
    if (clt->eth_ptag == -1)
    {
        fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(clt->lnet));
        return 1;
    }

    return 0;
}

client_t* client_init(char* dev, u_short port, u_char pri)
{
    srand((port << 16) & time(NULL));
    client_t* client = malloc(sizeof(client_t));
    client->src_port = port;
    client->terminate = 0;
    client->priority = pri;
    client->lock = malloc(sizeof(pthread_mutex_t));
    client->has_msg = malloc(sizeof(pthread_cond_t));
    pthread_mutex_init(client->lock, NULL);
    pthread_cond_init(client->has_msg, NULL);
    client->head = NULL;
    client->tail = NULL;

    /* Choose sequence number randomly */
    client->seq = rand();
    client->ack = client->seq;

    char err_buf[1024];
    client->pcap = pcap_open_live(dev, 65536, 1, TIMEOUT_MS, err_buf);
    if (client->pcap == NULL) {
        printf("pcap init error!\n");
        fprintf(stderr, "%s", err_buf);
        free(client);
        return NULL;
    }

    char pattern[64];
    sprintf(pattern, "tcp and dst port %d", client->src_port);
    struct bpf_program filter;
    pcap_compile(client->pcap, &filter, pattern, 1, 0);
    pcap_setfilter(client->pcap, &filter);

    client->lnet = libnet_init(LIBNET_LINK, NULL, err_buf);
    if (client->lnet == NULL) {
        printf("libnet init error!\n");
        fprintf(stderr, "%s", err_buf);
        pcap_close(client->pcap);
        free(client);
        return NULL;
    }

    if (pthread_create(&(client->thread), NULL, client_loop, client) != 0) {
        perror("can't create thread");
        pcap_close(client->pcap);
        libnet_destroy(client->lnet);
        free(client);
        return NULL;
    }

    return client;
}

void client_close(client_t* clt)
{
    pthread_mutex_lock(clt->lock);
    printf("terminate get lock\n");
    clt->terminate = 1;
    pthread_mutex_unlock(clt->lock);
    pthread_cond_signal(clt->has_msg);
    pthread_detach(clt->thread);
    pthread_join(clt->thread, NULL);

    pthread_mutex_destroy(clt->lock);
    pthread_cond_destroy(clt->has_msg);
    free(clt->lock);
    free(clt->has_msg);

    if (clt->pcap > 0) {
        pcap_close(clt->pcap);
    }
    if (clt->lnet > 0) {
        libnet_destroy(clt->lnet);
    }
    free(clt);
}

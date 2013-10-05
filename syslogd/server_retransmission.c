#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include "server.h"
#include "client.h"

#define PORT_MIN 49152
#define PORT_MAX 65536
#define CLIENT_NUM_MAX 256

pcap_t*         pcap;
libnet_t*       lnet;
int             src_num = 0;
char*           dev;
u_char          local_mac[MAC_LEN];
u_long          local_ip;
u_long          local_port;
libnet_ptag_t   udp_ptag = 0;
libnet_ptag_t   ipv4_ptag = 0;
libnet_ptag_t   eth_ptag = 0;
u_int           hop_number;
u_char          dst_mac[MAC_LEN];


client_t* server_client[CLIENT_NUM_MAX];
source_t sources[SOURCE_NUM_MAX];

FILE* file;

int server_client_build_packet(client_t* clt, char* payload, int payload_s, u_long seq, u_char flags)
{
    memcpy(payload + SEQ_OFFSET, &seq, sizeof(u_long));
    memcpy(payload + FLAG_OFFSET, &flags, sizeof(u_char));
    
    /* Build UDP header */
    clt->udp_ptag = libnet_build_udp(
                                     clt->src_port, /* source port */
                                     clt->dst_port, /* dst port */
                                     LIBNET_UDP_H + payload_s, /* length */
                                     0, /* checksum */
                                     payload, /* payload */
                                     payload_s, /* payload length */
                                     clt->lnet, /* libnet handle */
                                     clt->udp_ptag); /* libnet id */
    if (clt->udp_ptag == -1)
    {
        fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(clt->lnet));
        return 1;
    }
    
    /* Build ipv4 header */
    clt->ipv4_ptag = libnet_build_ipv4(
                                       LIBNET_IPV4_H + LIBNET_UDP_H + payload_s,/* length */
                                       0, /* TOS */
                                       242, /* IP ID */
                                       0, /* IP Frag */
                                       64, /* TTL */
                                       IPPROTO_UDP, /* protocol */
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

void client_free_messages(client_t* client)
{
    pthread_mutex_lock(client->lock);
    message_t* current = client->head;
    while (current != NULL && current->seq < client->ack)
    {
        client->head = current->next;
        free(current->msg);
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
    int offset = LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_UDP_H + SEQ_OFFSET;
    u_long ack;
    memcpy(&ack, data+offset, sizeof(u_long));
    return ack;
}

int match_source(source_t* source, u_long ip, u_short port)
{
    if (source->ip == ip && source->port == port) {
        return 1;
    } else {
        return 0;
    }
}

void insert_packet(source_t* source, packet_t* packet)
{
    if (packet->seq < source->seq) return;
    if (source->packets == NULL) {
        source->packets = packet;
    } else {
        if (packet->seq < source->packets->seq) {
            packet->next = source->packets;
            source->packets = packet;
        }
        else if (packet->seq > source->packets->seq) {
            packet_t* current = source->packets;
            while (current->next != NULL && current->next->seq < packet->seq) {
                current = current->next;
            }
            if (current->next == NULL || current->next->seq > packet->seq) {
                packet->next = current->next;
                current->next = packet;
            }
        }
    }
}

void free_packet(packet_t* p)
{
    free(p->data);
    free(p);
}

void save_packet(packet_t* p)
{
    fwrite(p->data+HEADER_LEN, p->len - HEADER_LEN, 1, file);
    fflush(file);
}

void send_ack(source_t* source)
{
    while (source->packets != NULL && source->seq == source->packets->seq) {
        save_packet(source->packets);
        packet_t* p = source->packets;
        source->packets = source->packets->next;
        free_packet(p);
        ++source->seq;
    }
    
    char payload[HEADER_LEN];
    memset(payload, 0, sizeof(payload));
    memcpy(payload + SEQ_OFFSET, &source->seq, sizeof(u_long));
    
    /* Build UDP header */
    udp_ptag = libnet_build_udp(
                                local_port, /* source port */
                                source->port, /* dst port */
                                LIBNET_UDP_H + HEADER_LEN, /* length */
                                0, /* checksum */
                                payload, /* payload */
                                HEADER_LEN, /* payload length */
                                lnet, /* libnet handle */
                                udp_ptag); /* libnet id */
    if (udp_ptag == -1)
    {
        fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(lnet));
        return;
    }
    
    /* Build ipv4 header */
    ipv4_ptag = libnet_build_ipv4(
                                  LIBNET_IPV4_H + LIBNET_UDP_H,/* length */
                                  0, /* TOS */
                                  242, /* IP ID */
                                  0, /* IP Frag */
                                  64, /* TTL */
                                  IPPROTO_UDP, /* protocol */
                                  0, /* checksum */
                                  local_ip, /* source IP */
                                  source->ip, /* destination IP */
                                  NULL, /* payload */
                                  0, /* payload size */
                                  lnet, /* libnet handle */
                                  ipv4_ptag); /* libnet id */
    if (ipv4_ptag == -1)
    {
        fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(lnet));
        return;
    }
    
    eth_ptag = libnet_build_ethernet(
                                     source->mac, /* ethernet destination */
                                     local_mac, /* ethernet source */
                                     ETHERTYPE_IP, /* protocol type */
                                     NULL, /* payload */
                                     0, /* payload size */
                                     lnet, /* libnet handle */
                                     eth_ptag); /* libnet id */
    if (eth_ptag == -1)
    {
        fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(lnet));
        return;
    }
    
    libnet_write(lnet);
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
    //memset(clt->dst_mac, 0, MAC_LEN);
    clt->dst_mac = dst_mac;
    clt->dst_mac[hop_number-1] = 1;
    
    /* Get source IP */
    clt->src_ip = libnet_get_ipaddr4(clt->lnet);
    if (clt->src_ip == 0)
    {
        perror(libnet_geterror(clt->lnet));
        return 1;
    }
    /* Set destination IP */
    struct in_addr* inp = malloc(sizeof(struct in_addr));
    if (inet_aton(LOG_IP, inp) == 0)
    {
        perror("destination ip error");
        return 1;
    }
    memcpy(&(clt->dst_ip), &(inp->s_addr), sizeof(u_long));
    free(inp);
    
    /* Set destination port */
    clt->dst_port = LOG_PORT;
    
    clt->udp_ptag = 0;
    clt->ipv4_ptag = 0;
    clt->eth_ptag = 0;
    
    return 0;
}

void* server_client_loop(void* client_ptr)
{
    client_t* server_client = (client_t*) client_ptr;
    if (client_init_fields(server_client) != 0)
    {
        fprintf(stderr, "Fields initialization failed!");
        return (void *)1;
    }
    
    message_t* current = NULL;
    
    while (1)
    {
        pthread_mutex_lock(server_client->lock);
        if (current == NULL)
            current = server_client->head;
        while (server_client->head == NULL)
        {
            if (server_client->terminate)
            {
                pthread_mutex_unlock(server_client->lock);
                return 0;
            }
            printf("client on port %d sleep\n", server_client->src_port);
            pthread_cond_wait(server_client->has_msg, server_client->lock);
            printf("client on port %d wake up\n", server_client->src_port);
            current = server_client->head;
        }
        while (current != NULL && current->seq < server_client->ack + WIN_SIZE)
        {
            u_char flags = TH_PUSH;
            if (current->seq == server_client->ack)
            {
                flags = TH_PUSH | TH_SYN;
            }
            server_client_build_packet(server_client, current->msg,current->msg_s,current->seq, flags);
            libnet_write(server_client->lnet);
            printf("port %d sended out seq: %x\n", server_client->src_port, current->seq);
            current = current->next;
        }
        pthread_mutex_unlock(server_client->lock);
        
        struct pcap_pkthdr* pkthdr;
        const u_char* pkt_data;
        int rval = pcap_next_ex(server_client->pcap, &pkthdr, &pkt_data);
        switch (rval)
        {
            case 1:
                if (pkthdr->caplen == pkthdr->len)
                {
                    server_client->ack = client_parse_ack(pkt_data);
                    printf("received ack: %x\n", server_client->ack);
                    client_free_messages(server_client);
                }
                break;
            case 0:
                current = server_client->head;
                break;
            default:
                pcap_perror(server_client->pcap, "pcap_next_ex error");
                break;
        }
    }
    return 0;
}

client_t* server_client_init(char* dev, u_short port)
{
    client_t* server_client = malloc(sizeof(client_t));
    server_client->src_port = port;
    server_client->terminate = 0;
    server_client->lock = malloc(sizeof(pthread_mutex_t));
    server_client->has_msg = malloc(sizeof(pthread_cond_t));
    pthread_mutex_init(server_client->lock, NULL);
    pthread_cond_init(server_client->has_msg, NULL);
    server_client->head = NULL;
    server_client->tail = NULL;
    
    /* Choose sequence number randomly */
    server_client->seq = rand();
    server_client->ack = server_client->seq;
    
    char err_buf[1024];
    server_client->pcap = pcap_open_live(dev, 65536, 1, TIMEOUT_MS, err_buf);   //Wait for ACK (server-to-server)
    if (server_client->pcap == NULL) {
        printf("pcap init error!\n");
        fprintf(stderr, "%s", err_buf);
        free(server_client);
        return NULL;
    }
    
    char pattern[64];
    sprintf(pattern, "udp and src port %d and dst port %d", LOG_PORT, server_client->src_port);
    struct bpf_program filter;
    pcap_compile(server_client->pcap, &filter, pattern, 1, 0);
    pcap_setfilter(server_client->pcap, &filter);
    
    server_client->lnet = libnet_init(LIBNET_LINK, dev, err_buf);
    if (server_client->lnet == NULL)
    {
        printf("libnet init error!\n");
        fprintf(stderr, "%s", err_buf);
        pcap_close(server_client->pcap);
        free(server_client);
        return NULL;
    }
    
    if (pthread_create(&(server_client->thread), NULL, server_client_loop, server_client) != 0)
    {
        perror("can't create thread");
        pcap_close(server_client->pcap);
        libnet_destroy(server_client->lnet);
        free(server_client);
        return NULL;
    }
    
    return server_client;
}

int server_client_send(client_t* clt, u_char* msg, int len)
{
    pthread_mutex_lock(clt->lock);
    
    message_t* new_msg = malloc(sizeof(message_t));
    new_msg->seq = clt->seq;
    clt->seq += 1;
    new_msg->msg = malloc(len + HEADER_LEN);
    memset(new_msg->msg, 0, HEADER_LEN);
    memcpy(new_msg->msg + HEADER_LEN, msg, len);
    new_msg->msg_s = len + HEADER_LEN;
    new_msg->next = NULL;
    if (clt->tail == NULL) {
        clt->head = new_msg;
        clt->tail = new_msg;
    } else {
        clt->tail->next = new_msg;
        clt->tail = new_msg;
    }
    
    pthread_mutex_unlock(clt->lock);
    pthread_cond_signal(clt->has_msg);
}


void parse_packet(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    if (pkthdr->caplen < pkthdr->len) return;
    
    u_long  src_ip;
    u_long  seq;
    u_short src_port;
    u_char  flags;
    u_char  src_mac[MAC_LEN];
    u_char* payload;
    u_long  payload_s;
    
    memcpy(&src_mac, packet+SRC_MAC_OFFSET, MAC_LEN);
    memcpy(&dst_mac, packet+SRC_MAC_OFFSET+MAC_LEN, MAC_LEN);
    memcpy(&src_ip, packet+LIBNET_ETH_H+SRC_IP_OFFSET, IP_LEN);
    memcpy(&src_port, packet+LIBNET_ETH_H+LIBNET_IPV4_H+SRC_PORT_OFFSET, PORT_LEN);
    memcpy(&seq, packet+LIBNET_ETH_H+LIBNET_IPV4_H+LIBNET_UDP_H+SEQ_OFFSET, SEQ_LEN);
    memcpy(&flags, packet+LIBNET_ETH_H+LIBNET_IPV4_H+LIBNET_UDP_H+FLAG_OFFSET, sizeof(u_char));
    
    src_port = ntohs(src_port);
    
    packet_t* newp = malloc(sizeof(packet_t));
    int offset = LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_UDP_H;
    int len = pkthdr->len - offset;
    newp->seq = seq;
    newp->data = malloc(len);
    memcpy(newp->data, packet + offset, len);
    newp->len = len;
    newp->next = NULL;
    
    int s = 0;
    while (s < src_num && !match_source(&sources[s], src_ip, src_port)) ++s;
    
    if (s >= src_num && (flags & TH_SYN)) {
        s = src_num++;
        sources[s].ip = src_ip;
        sources[s].port = src_port;
        sources[s].seq = seq;
        sources[s].packets = newp;
    } else {
        insert_packet(&sources[s], newp);
    }
    memcpy(sources[s].mac, src_mac, MAC_LEN);
    
    
    
    if(server_client[s] == 0)
    {
        u_short port = PORT_MIN + rand() % (PORT_MAX - PORT_MIN);
        server_client[s] = server_client_init(dev, port);
    }
    server_client_send(server_client[s], newp->data, len);
    
    
    send_ack(&sources[s]);
}

int set_local_fields() {
    /* Get local MAC */
    struct libnet_ether_addr* src_hwaddr = libnet_get_hwaddr(lnet);
    if (src_hwaddr == NULL) {
        perror(libnet_geterror(lnet));
        return 1;
    }
    memcpy(local_mac, src_hwaddr->ether_addr_octet, MAC_LEN);
    
    /* Set local IP by LOG_IP*/
    struct in_addr* inp = malloc(sizeof(struct in_addr));
    if (inet_aton(LOG_IP, inp) == 0) {
        perror("Failed to set local ip");
        return 1;
    }
    memcpy(&local_ip, &(inp->s_addr), sizeof(u_long));
    free(inp);
    
    local_port = LOG_PORT;
    return 0;
}

void client_close(client_t* clt)
{
    pthread_mutex_lock(clt->lock);
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

int main(int agrc, char** argv)
{
    char err_buf[1024];
    dev = argv[1];
    file = fopen(argv[2], "w+");
    hop_number = argv[3];
    pcap = pcap_open_live(dev, 65536, 1, 0, err_buf);
    if (pcap == NULL) {
        printf("pcap init error!\n");
        fprintf(stderr, "%s", err_buf);
        return 1;
    }
    lnet = libnet_init(LIBNET_LINK, dev, err_buf);
    if (lnet == NULL) {
        printf("libnet init error!\n");
        fprintf(stderr, "%s", err_buf);
        pcap_close(pcap);
        return 1;
    }
    if (set_local_fields() != 0) {
        printf("set_local_fields failed\n");
        return 1;
    }
    
    char pattern[64];
    sprintf(pattern, "udp and dst port %d", LOG_PORT);
    struct bpf_program filter;
    pcap_compile(pcap, &filter, pattern, 1, 0);
    pcap_setfilter(pcap, &filter);
    
    memset(sources, 0, sizeof(sources));
    pcap_loop(pcap, -1, parse_packet, NULL);
    
    libnet_destroy(lnet);
    pcap_close(pcap);
    fclose(file);
    
    int i;
    for (i = 0; i < CLIENT_NUM_MAX; ++i)
    {
        if (server_client[i] != 0)
        {
            client_close(server_client[i]);
        }
    }
    
    
    return 0;
}

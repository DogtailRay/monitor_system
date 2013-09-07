#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include "server.h"

pcap_t* pcap;
libnet_t* lnet;
int src_num = 0;

u_char local_mac[MAC_LEN];
u_long local_ip;
u_long local_port;

libnet_ptag_t udp_ptag = 0;
libnet_ptag_t ipv4_ptag = 0;
libnet_ptag_t eth_ptag = 0;

source_t sources[SOURCE_NUM_MAX];

FILE* file;

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

void parse_packet(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    if (pkthdr->caplen < pkthdr->len) return;

    u_long src_ip;
    u_long seq;
    u_short src_port;
    u_char flags;
    u_char src_mac[MAC_LEN];

    memcpy(&src_mac, packet+SRC_MAC_OFFSET, MAC_LEN);
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

int main(int agrc, char** argv)
{
    char err_buf[1024];
    char* dev = argv[1];
    file = fopen(argv[2], "w+");
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
    return 0;
}

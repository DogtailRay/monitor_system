#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include "msg_sender.h"

sender_s* msg_sender_init(char* iface)
{
    sender_s* sender = malloc(sizeof(sender_s));
    char err_buff[LIBNET_ERRBUF_SIZE];
    sender->l = libnet_init(LIBNET_LINK, iface, err_buff);
    if (sender->l == NULL) {
        printf("libnet init err!\n");
        fprintf(stderr, "%s", err_buff);
        return NULL;
    }

    memset(sender->dest_mac, 0x11, MAC_LEN);
    msg_sender_get_src_mac(sender->l, sender->src_mac);
    sender->p_tag = 0;
    return sender;
}

void msg_sender_get_src_mac(libnet_t* l, u_char* src_mac)
{
    struct libnet_ether_addr* src_hwaddr = libnet_get_hwaddr(l);
    memcpy(src_mac, src_hwaddr->ether_addr_octet, MAC_LEN);
}

void msg_sender_close(sender_s* sender)
{
    libnet_destroy(sender->l);
    free(sender);
}

u_char msg_parser_priority(char* msg, unsigned msg_len)
{
    int p = 0;
    while (msg[p] != '<' && p < msg_len) ++p;
    if (p >= msg_len) return 0;
    ++p;
    u_char pri = 0;
    while (msg[p] != '>' && p < msg_len) {
        pri = pri * 10 + msg[p] - '0';
        ++p;
    }
    if (p >= msg_len) return 0;
    return pri;
}

int msg_sender_send(sender_s* sender, char* msg, u_short msg_len)
{
    // rsyslog: priority = facility << 3 + severity
    u_char priority = msg_parser_priority(msg,msg_len);
    u_char md5[16];
    MD5(msg,msg_len,md5);
    // data is the payload of ethernet package
    char* data = malloc(DATA_MAX_LEN);
    memset(data, 0, DATA_MAX_LEN);
    memcpy(data + LEN_OFFSET, &msg_len, sizeof(u_short));
    memcpy(data + MD5_OFFSET, md5, 16);
    memcpy(data + PRI_OFFSET, &priority, sizeof(u_char));
    sender->proto = (0xaa << 8) + priority;

    int max_len = DATA_MAX_LEN - TCP_IP_HLEN;
    int sent_len = 0;
    char* payload = data + PAYLOAD_OFFSET;
    u_char idx = 0;
    while (sent_len < msg_len) {
        // l is the length of payload in current package
        int l = msg_len - sent_len;
        if (l > max_len) l = max_len;
        //printf("l: %d\n",l);
        //printf("sent len: %d\n",sent_len);
        memcpy(payload, msg+sent_len, l);
        memcpy(data + IDX_OFFSET, &idx, sizeof(u_char));
        msg_sender_send_out(sender, data, PAYLOAD_OFFSET + l);
        //printf("%d\n", PAYLOAD_OFFSET + l);
        sent_len += l;
        ++idx;
    }
    free(data);
}

int msg_sender_send_out(sender_s* sender, char* data, u_short data_len)
{
    // Careful with the last parameter, specify p_tag to modify an existing header
    // 0 to create new header. If have to send multiple packages, don't creat new header
    // every time, modify an existing one instead. Otherwise strange things will happen.
    sender->p_tag = libnet_build_ethernet(sender->dest_mac, sender->src_mac, sender->proto,
            data, data_len, sender->l, sender->p_tag);
    // Send the packet
    if (sender->p_tag == -1) {
        sender->p_tag = 0;
        printf("libnet_build_ethernet err!\n");
        return -1;
    }

    if (libnet_write(sender->l) == -1) {
        printf("libnet_write err!\n");
    } else {
        //printf("libnet_write succeeded!\n");
    }

    return 0;
}

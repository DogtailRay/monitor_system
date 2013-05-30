#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "msg_sender.h"

sender_s* msg_sender_init()
{
    sender_s* sender = malloc(sizeof(sender_s));
    sender->iface = "eth0";
    unsigned char dest_array[ETH_ALEN] = { 0x00, 0x12, 0x34, 0x56, 0x78, 0x90 };
    memcpy(sender->dest, dest_array, ETH_ALEN);
    sender->proto = 0x00;

    // Build the socket
    sender->s = socket(AF_PACKET, SOCK_RAW, htons(sender->proto));
    if (sender->s < 0) {
        printf("Can't open the socket, root privilege is needed!\n");
        free(sender);
        return NULL;
    }

    // Look up interface properties
    struct ifreq buffer;
    int ifindex;
    memset(&buffer, 0x00, sizeof(buffer));
    strncpy(buffer.ifr_name, sender->iface, IFNAMSIZ);
    if (ioctl(sender->s, SIOCGIFINDEX, &buffer) < 0) {
        printf("Error: could not get interface index\n");
        close(sender->s);
        free(sender);
        return NULL;
    }
    ifindex = buffer.ifr_ifindex;
    printf("ifindex: %d\n", ifindex);

    // Look up source MAC address
    if (ioctl(sender->s, SIOCGIFHWADDR, &buffer) < 0) {
        printf("Error: could not get interface address\n");
        close(sender->s);
        free(sender);
        return NULL;
    }
    memcpy((void*)(sender->source), (void*)(buffer.ifr_hwaddr.sa_data), ETH_ALEN);

    // Print source MAC address
    int i = 0;
    printf("Source MAC: ");
    for (i = 0; i < ETH_ALEN; ++i) {
        if (i > 0) printf(":");
        printf("%02x", sender->source[i]);
    }
    printf("\n");

    // Fill in the packet fields
    memcpy(sender->frame.field.header.h_dest, sender->dest, ETH_ALEN);
    memcpy(sender->frame.field.header.h_source, sender->source, ETH_ALEN);
    sender->frame.field.header.h_proto = htons(sender->proto);

    // Fill in the sockaddr_ll struct
    memset((void*)&(sender->saddrll), 0, sizeof(sender->saddrll));
    sender->saddrll.sll_family = PF_PACKET;
    sender->saddrll.sll_ifindex = ifindex;
    sender->saddrll.sll_halen = ETH_ALEN;
    memcpy((void*)(sender->saddrll.sll_addr), (void*)(sender->dest), ETH_ALEN);

    return sender;
}

void msg_sender_close(sender_s* sender)
{
    close(sender->s);
    free(sender);
}

int msg_sender_send(const sender_s* sender, const char* data, const unsigned data_len)
{
    union ethframe frame;
    memcpy(frame.buffer, sender->frame.buffer, sizeof(frame.buffer));
    memcpy(frame.field.data, data, data_len);

    // Send the packet
    unsigned int frame_len = data_len + ETH_HLEN;
    if (sendto(sender->s, frame.buffer, frame_len, 0,
                (struct sockaddr*)&(sender->saddrll), sizeof(sender->saddrll)) > 0) {
        printf("Success!\n");
    } else {
        printf("Failed!\n");
        return -1;
    }

    return 0;
}

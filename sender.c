#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Headers for sending raw ethernet packages */
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

/* Headers for interprocess messages */
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#define ClientType 44
#define ServerType 33
#define MSG_KEY 23          // To identify message pipe
#define MSG_MAX_LEN 8096     // 1024 is just for test

// Raw ethernet packet struct
union ethframe
{
    struct
    {
        struct ethhdr header;
        unsigned char data[ETH_DATA_LEN];
    } field;
    unsigned char buffer[ETH_FRAME_LEN];
};

struct log_message_s
{
    long mtype;
    char buffer[MSG_MAX_LEN];
} message;

int msgid;

int main(int argc, char** argv)
{
    /* Send raw ethernet packet */
    char* iface = "eth0";
    unsigned char dest[]
        = { 0x00, 0x12, 0x34, 0x56, 0x78, 0x90 };
    unsigned short proto = 0x00;
    char* data = "Hello World!";
    unsigned short data_len = strlen(data);

    // Get root privilege
    printf("setuid result: %d\n", setuid(0));

    // Build the socket
    int s = socket(AF_PACKET, SOCK_RAW, htons(proto));
    if (s < 0) {
        printf("Can't open the socket, root privilege is needed!\n");
        return -1;
    }
    // Look up interface properties
    struct ifreq buffer;
    int ifindex;
    memset(&buffer, 0x00, sizeof(buffer));
    strncpy(buffer.ifr_name, iface, IFNAMSIZ);
    if (ioctl(s, SIOCGIFINDEX, &buffer) < 0) {
        printf("Error: could not get interface index\n");
        close(s);
        return -1;
    }
    ifindex = buffer.ifr_ifindex;
    printf("ifindex: %d\n", ifindex);
    // Look up source MAC address
    unsigned char source[ETH_ALEN];
    if (ioctl(s, SIOCGIFHWADDR, &buffer) < 0) {
        printf("Error: could not get interface address\n");
        close(s);
        return -1;
    }
    memcpy((void*)source, (void*)(buffer.ifr_hwaddr.sa_data), ETH_ALEN);

    // Print source MAC address
    int i = 0;
    printf("Source MAC: ");
    for (i = 0; i < ETH_ALEN; ++i) {
        if (i > 0) printf(":");
        printf("%02x", source[i]);
    }
    printf("\n");

    // Fill in the packet fields
    union ethframe frame;
    memcpy(frame.field.header.h_dest, dest, ETH_ALEN);
    memcpy(frame.field.header.h_source, source, ETH_ALEN);
    frame.field.header.h_proto = htons(proto);
    memcpy(frame.field.data, data, data_len);

    // Fill in the sockaddr_ll struct
    struct sockaddr_ll saddrll;
    memset((void*)&saddrll, 0, sizeof(saddrll));
    saddrll.sll_family = PF_PACKET;
    saddrll.sll_ifindex = ifindex;
    saddrll.sll_halen = ETH_ALEN;
    memcpy((void*)(saddrll.sll_addr), (void*)dest, ETH_ALEN);

    // Initialize message server
    msgid = msgget(MSG_KEY, IPC_CREAT|IPC_EXCL|0666);
    if (msgid < 0)
    {
        printf("Message pipe already exists!");
        close(s);
        return -1;
    }
    printf("Message server started! qid:%d\n", msgid);

    while (1) {
        msgrcv(msgid, &message, sizeof(message), ClientType, 0);
        printf("Received message: %s\n", message.buffer);
        data_len = strlen(message.buffer);          // Using strlen is dangerous, we need a better function
        memcpy(frame.field.data, message.buffer, data_len);

        // Send the packet
        unsigned int frame_len = data_len + ETH_HLEN;
        if (sendto(s, frame.buffer, frame_len, 0,
                    (struct sockaddr*)&saddrll, sizeof(saddrll)) > 0) {
            printf("Success!\n");
        } else {
            printf("Failed!\n");
            close(s);
            return -1;
        }

    }

    close(s);

    return 0;
}

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

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

// Message sender struct
typedef struct msg_sender_s
{
    char* iface;
    unsigned char dest[ETH_ALEN];
    unsigned char source[ETH_ALEN];
    unsigned short proto;
    int s;
    union ethframe frame;
    struct sockaddr_ll saddrll;
} sender_s;

sender_s* msg_sender_init();
int msg_sender_send(const sender_s* sender, const char* data, const unsigned data_len);
void msg_sender_close(sender_s* sender);

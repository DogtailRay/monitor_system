#include <libnet.h>

#define MAC_LEN 6
#define TCP_IP_HLEN 40
#define DATA_MAX_LEN 50
#define PRI_OFFSET 0
#define PAYLOAD_OFFSET TCP_IP_HLEN

// Message sender struct
typedef struct msg_sender_s
{
    char* device;
    u_char dest_mac[MAC_LEN];
    u_char src_mac[MAC_LEN];
    u_short proto;
    libnet_t *l;
    libnet_ptag_t p_tag;
} sender_s;

sender_s* msg_sender_init();

// Parse data then send out
int msg_sender_send(sender_s* sender, char* msg, unsigned msg_len);
// Send out directly
int msg_sender_send_out(sender_s* sender, char* data, unsigned data_len);
void msg_sender_close(sender_s* sender);
void msg_sender_get_src_mac(libnet_t *l, u_char* src_mac);

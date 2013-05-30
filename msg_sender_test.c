#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "msg_sender.h"

int main() {
    char* data = "Hello World!";
    unsigned data_len = strlen(data);
    sender_s* sender = msg_sender_init();
    if (sender == NULL) {
        printf("Init failed!\n");
        return -1;
    }
    msg_sender_send(sender, data, data_len);
    msg_sender_close(sender);
}

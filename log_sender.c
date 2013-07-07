#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "msg_sender.h"
/* Headers for interprocess messages */
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#define ClientType 44
#define ServerType 33
#define MSG_KEY 23          // To identify message pipe
#define MSG_MAX_LEN 8096     // 1024 is just for test

struct log_message_s
{
    long mtype;
    char buffer[MSG_MAX_LEN];
} message;

int msgid;

int main(int argc, char** argv)
{
    // Initialize message server
    msgid = msgget(MSG_KEY, IPC_CREAT|IPC_EXCL|0666);
    if (msgid < 0)
    {
        printf("Message pipe already exists!");
        return -1;
    }
    printf("Message server started! qid:%d\n", msgid);

    sender_s* sender = msg_sender_init(argv[1]);
    if (sender == NULL) {
        printf("Message sender init failed!\n");
        return -1;
    }

    while (1) {
        memset(message.buffer, 0, sizeof(message.buffer));
        msgrcv(msgid, &message, sizeof(message), ClientType, 0);
        printf("Received message: %s\n", message.buffer);
        int data_len = strlen(message.buffer);
        msg_sender_send(sender, message.buffer, data_len);
    }
    msg_sender_close(sender);
    return 0;
}

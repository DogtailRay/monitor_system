#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "client.h"

#define LOG_FILE "/dev/log"
#define BUF_SIZE 65536
#define PORT_MIN 49152
#define PORT_MAX 65536

#define CLIENT_NUM_MAX 256

client_t* clients[CLIENT_NUM_MAX];

char* dev;

void parse_log(char* log, int size)
{
    printf("received log: %s\n", log);
    u_char pri = client_extract_priority(log, size);
    if (clients[pri] == 0) {
        u_short port = PORT_MIN + rand() % (PORT_MAX - PORT_MIN);
        clients[pri] = client_init(dev, port, pri);
    }
    client_send(clients[pri], log, size);
}

int main(int agrc, char** argv)
{
    dev = argv[1];
    srand(time(NULL));
    int sock, msgsock, rval;
    struct sockaddr_un server;
    char buffer[BUF_SIZE];

    sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("opening stream socket");
        exit(1);
    }
    server.sun_family = AF_UNIX;
    strcpy(server.sun_path, LOG_FILE);
    unlink(LOG_FILE);
    if (bind(sock, (struct sockaddr *)&server, sizeof(struct sockaddr_un))) {
        perror("binding stream socket");
        exit(1);
    }

    if (chmod(LOG_FILE, S_IROTH | S_IWOTH) < 0) {
        perror("changing permission");
        exit(1);
    }

    memset(clients, 0, sizeof(clients));

    listen(sock, 50);
    /*while (1) {
        msgsock = accept(sock, 0, 0);
        if (msgsock < 0) perror("accept");
        else do {
            bzero(buffer, sizeof(buffer));
            rval = read(msgsock, buffer, 1024);
            if (rval < 0)
                perror("reading stream message");
            else if (rval == 0)
                printf("Ending connection\n");
            else
                printf("-->%s\n", buffer);
        } while (rval > 0);
    }*/

    while (1) {
        bzero(buffer, sizeof(buffer));
        rval = read(sock, buffer, BUF_SIZE);
        if (rval < 0)
            perror("reading stream message");
        else
            parse_log(buffer, strlen(buffer));
    }

    close(sock);
    int i;
    for (i = 0; i < CLIENT_NUM_MAX; ++i) {
        if (clients[i] != 0) {
            client_close(clients[i]);
        }
    }
}

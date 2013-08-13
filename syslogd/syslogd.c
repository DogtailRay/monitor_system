#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_FILE "/dev/log"
#define BUF_SIZE 65536

int main() {
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
            printf("-->%s\n", buffer);
    }
    close(sock);
}

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

int main(int argc, char** argv)
{
    openlog("Syslog Test", LOG_NOWAIT, LOG_USER);
    pid_t pid = fork();
    pid = fork();
    pid = fork();
    pid = fork();
    pid = fork();
    pid = getpid();
    syslog(LOG_INFO, "AAAAA This is INFO from process: %d", pid);
    syslog(LOG_DEBUG, "BBBBB This is DEBUG from process: %d", pid);
    closelog();
    return 0;
}

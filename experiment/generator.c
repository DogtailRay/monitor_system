#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

int main(int argc, char** argv)
{
    openlog("Syslog Test", LOG_NOWAIT, LOG_USER);
    pid_t pid;
    pid = getpid();
    syslog(LOG_INFO, "AAAAA This is INFO from host: %s process: %d", argv[1], pid);
    syslog(LOG_DEBUG, "BBBBB This is DEBUG from host: %s process: %d", argv[1], pid);
    syslog(LOG_ERR, "CCCCC This is ERROR from host: %s process: %d", argv[1], pid);
    syslog(LOG_WARNING, "DDDDD This is WARNING from host: %s process: %d", argv[1], pid);
    closelog();
    return 0;
}

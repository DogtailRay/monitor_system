#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

int main(int argc, char** argv)
{
    openlog("Syslog Test", LOG_NOWAIT, LOG_USER);
    int seq = 0;
    while(1) {
        int i;
        for (i = 0; i < 5; ++i,++seq) {
            syslog(LOG_INFO, "AAAAA This is INFO seq: %d", seq);
            syslog(LOG_DEBUG, "BBBBB This is DEBUG seq: %d", seq);
        }
        sleep(1);
    }
    closelog();
    return 0;
}

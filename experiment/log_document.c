#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>

int main(int argc, char** argv)
{
    srand(time(NULL));
    openlog("Syslog Test", LOG_NOWAIT, LOG_USER);
    FILE* doc = fopen(argv[1],"r");
    char buffer[1024];
    while (!feof(doc)) {
        fgets(buffer, sizeof(buffer), doc);
        printf("LOGGING: %s", buffer);
        syslog(LOG_INFO, "%s", buffer);
        sleep((rand() % 100) * 0.1);
    }
    fclose(doc);
    closelog();
    return 0;
}

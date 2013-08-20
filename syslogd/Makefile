ALL : syslogd server

syslogd : syslogd.c client.h client.c common.h
	gcc syslogd.c client.c -o syslogd -lnet -lpcap -lpthread

server : server.c server.h common.h
	gcc server.c -o server -lnet -lpcap -lpthread

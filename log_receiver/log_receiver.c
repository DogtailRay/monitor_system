#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log_receiver.h"

lrecv_t* log_receiver_init(const char* dev, const char* logfile)
{
    lrecv_t* l = malloc(sizeof(lrecv_t));
    char errbuf[1024];
    l->pcap = pcap_open_live(dev, 65536, 1, 0, errbuf);
    if (l->pcap == NULL){
        printf("Failed to open %s: %s\n",dev,errbuf);
        free(l);
        return NULL;
    }
    else {
        l->logfile = malloc(strlen(logfile)+1);
        strcpy(l->logfile, logfile);
        memset(l->pending_list, 0, sizeof(l->pending_list));
        l->pending_length = 0;
        return l;
    }
}

void log_receiver_close(lrecv_t* l)
{
    if (l != NULL) {
        pcap_close(l->pcap);
        free(l->logfile);
        free(l);
    }
}

void log_receiver_loop(lrecv_t* l, int cnt)
{
    struct bpf_program filter;
    pcap_compile(l->pcap, &filter, "ether dst 11:11:11:11:11:11", 1, 0);
    pcap_setfilter(l->pcap, &filter);
    pcap_loop(l->pcap, cnt, log_receiver_parse_packet, (u_char*)l);
}

void log_receiver_parse_packet(u_char* l, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    //printf("Got a packet:\n");
    //printf("caplen: %d len: %d\n", pkthdr->caplen, pkthdr->len);
    /*int i = 0;
    for (i = 0; i < pkthdr->caplen; ++i) {
        if (i % 20 == 0 && i > 0) printf("\n");
        printf("%02x ", packet[i]);
    }
    printf("\n");*/

    if (pkthdr->caplen < pkthdr->len) return;
    char* data = malloc(pkthdr->len - ETH_HLEN);
    memcpy(data, packet+ETH_HLEN, pkthdr->len - ETH_HLEN);
    pmsg_t* msg = malloc(sizeof(pmsg_t));
    memset(msg, 0, sizeof(pmsg_t));
    memcpy(&(msg->idx), data+IDX_OFFSET, sizeof(u_char));
    memcpy(&(msg->len), data+LEN_OFFSET, sizeof(u_short));
    memcpy(&(msg->priority), data+PRI_OFFSET, sizeof(u_char));
    memcpy(msg->md5, data+MD5_OFFSET, sizeof(msg->md5));
    msg->c_len = pkthdr->len - ETH_HLEN - PAYLOAD_OFFSET;
    memcpy(msg->content, data+PAYLOAD_OFFSET, msg->c_len);

    if (msg->c_len < msg->len) {
        log_receiver_pend_msg((lrecv_t*)l, msg);
    }
    else {
        log_receiver_log_msg((lrecv_t*)l, msg);
    }

    free(data);
}

void log_receiver_pend_msg(lrecv_t* l, pmsg_t* msg)
{
    //printf("begin pend msg\n");
    int i = 0;
    pmsg_t** list = l->pending_list;
    while (i < l->pending_length) {
        if (log_receiver_cmp_md5(list[i]->md5, msg->md5)) {
            list[i] = log_receiver_insert_msg(list[i], msg);
            break;
        }
        ++i;
    }
    if (i >= l->pending_length) {
        if (l->pending_length >= MAX_PENDING_LEN) {
            i = 0;
            printf("Pending list is full, the message is dropped.\n");
        }
        else {
            l->pending_length += 1;
            list[i] = msg;
        }
    }
    if (log_receiver_msg_complete(list[i])) {
        log_receiver_log_msg(l,list[i]);
        list[i] = list[l->pending_length - 1];
        list[l->pending_length - 1] = 0;
        l->pending_length -= 1;
    }
    //printf("end pend msg\n");
}

void log_receiver_log_msg(lrecv_t* l, pmsg_t* msg)
{
    int len = msg->len;
    u_char priority = msg->priority;
    u_char md5[16];
    memcpy(md5, msg->md5, 16);
    char* content = malloc(len + 1);
    memset(content, 0, len+1);
    int offset = 0;
    while (msg != NULL) {
        memcpy(content+offset, msg->content, msg->c_len);
        offset += msg->c_len;
        pmsg_t* pre_msg = msg;
        msg = msg->next;
        free(pre_msg);
    }

    u_char new_md5[16];
    MD5(content, len, new_md5);
    if (log_receiver_cmp_md5(md5, new_md5)) {
        FILE* file = fopen(l->logfile, "a");
        fprintf(file, "%d: %s\n", priority, content);
        fclose(file);
    } else {
        printf("MD5 validation failed! The message will not be logged!\n");
        printf("%s\n",content);
    }

    free(content);
}

int log_receiver_cmp_md5(const u_char* a, const u_char* b)
{
    int i;
    int result = 1;
    for (i = 0; i < 16; ++i) {
        if (a[i] != b[i]) {
            result = 0;
            break;
        }
    }
    return result;
}

pmsg_t* log_receiver_insert_msg(pmsg_t* head, pmsg_t* msg)
{
    //printf("begin insert msg\n");
    pmsg_t* current = head;
    pmsg_t* pre = NULL;
    while (current != NULL && current->idx <= msg->idx) {
        if (current->idx == msg->idx) return head;
        pre = current;
        current = current->next;
    }
    if (pre == NULL) {
        msg->next = current;
        return msg;
    }
    else {
        pre->next = msg;
        msg->next= current;
        return head;
    }
    //printf("end insert msg\n");
}

int log_receiver_msg_complete(pmsg_t* msg)
{
    //printf("begin msg complete\n");

    int length = msg->len;
    int total_length = 0;
    while (msg != NULL) {
        total_length += msg->c_len;
        msg = msg->next;
    }

    //printf("end msg complete\n");
    if (total_length >= length) {
        return 1;
    }
    else {
        return 0;
    }
}

int main(int argc, char** argv)
{
    lrecv_t* l = log_receiver_init(argv[1],argv[2]);
    if (l != NULL) {
        log_receiver_loop(l,-1);
        log_receiver_close(l);
    }
    return 0;
}

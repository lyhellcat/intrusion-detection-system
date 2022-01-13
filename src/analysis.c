#define _GNU_SOURCE

#include "analysis.h"
#include "dispatch.h"

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>

typedef struct _IP_node {
    struct in_addr ip_addr;
    struct _IP_node *next;
} IP_node;

IP_node *IP_list;
int syn_packets_count;
int arp_packets_count;
int violations_count;
int IP_list_len;
tpool_t *tm;

void add_list(struct in_addr ip_addr) {
    IP_node *p = IP_list;
    while (p != NULL) {
        if (p->ip_addr.s_addr == ip_addr.s_addr)
          return;
        p = p->next;
    }
    IP_node *new_node = calloc(1, sizeof(IP_node));
    if (IP_list == NULL) {
        IP_list = new_node;
    } else {
        new_node->next = IP_list->next;
        IP_list->next = new_node;
    }
    IP_list_len++;
}

void free_list() {
    IP_node *p = IP_list;
    IP_node *q = IP_list;
    while (p != NULL) {
        q = p;
        p = p->next;
        free(q);
    }
}

void signal_handler(int signo) {
    if (signo == SIGINT) {
        puts("\nIntrusion Detection Report: ");
        printf("%d SYN packets  detected from %d different IPs (syn attack)\n",
                syn_packets_count, IP_list_len);
        printf("%d ARP responses (cache poisoning)\n", arp_packets_count);
        printf("%d URL Blacklist violations\n", violations_count);
        tpool_wait(tm);
        tpool_destroy(tm);
        free_list();
        exit(EXIT_SUCCESS);
    }
    assert(false);
}

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void analyse(void *args) {
    printf("----> %d <-----\n ", gettid());
    pthread_mutex_lock(&mutex);
    // Unpack arguments
    const struct pcap_pkthdr *header = ((struct arguments *)args)->header;
    const unsigned char *packet = ((struct arguments *)args)->packet;
    int verbose = ((struct arguments *)args)->verbose;
    tm = ((struct arguments *)args)->tm;
    // Handler ^C signal
    struct sigaction action = {.sa_handler = signal_handler};
    sigaction(SIGINT, &action, NULL);
    // Get Ethernet header
    struct ether_header *eth_ptr = (struct ether_header *)packet;
    unsigned short ether_type = ntohs(eth_ptr->ether_type);
    if (ether_type == ETHERTYPE_IP) {  // IP type
        struct ip *ip_ptr =
            (struct ip *)(packet += sizeof(struct ether_header));
        if (ip_ptr->ip_p == IPPROTO_TCP) {  // TCP Protocal
            struct tcphdr *tcp_ptr =
                (struct tcphdr *)(packet += ip_ptr->ip_hl * 4);
            if (tcp_ptr->syn) {
                syn_packets_count++;
                add_list(ip_ptr->ip_src);
            }
            if (ntohs(tcp_ptr->dest) == 80) { // HTTP
                char *payload = (char *)(packet += tcp_ptr->th_off * 4);
                if (strstr(payload, "Host: www.google.co.uk") != NULL ||
                    strstr(payload, "Host: www.bbc.com") != NULL) {
                    puts("=============================");
                    puts("Blacklisted URL violation detected");
                    printf("Source IP address: %s\n", inet_ntoa(ip_ptr->ip_src));
                    printf("Destination IP address: %s\n", inet_ntoa(ip_ptr->ip_dst));
                    puts("=============================");
                    violations_count++;
                }
            }
        }
    } else if (ether_type == ETHERTYPE_ARP) { // ARP packet
        arp_packets_count++;
    }
    // free(((struct arguments *)args)->packet);
    pthread_mutex_unlock(&mutex);
}

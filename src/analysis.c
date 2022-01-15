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
#include <limits.h>
#include <stdint.h>

#define MAC_STR_LEN 20

typedef uint32_t word_t;
enum { BITS_PER_WORD = sizeof(word_t) * CHAR_BIT };
#define WORD_OFFSET(b) ((b) / BITS_PER_WORD)
#define BIT_OFFSET(b) ((b) % BITS_PER_WORD)

tpool_t *tm;
static int syn_packets_count;
static int arp_packets_count;
static int violations_count;
static int IP_addr_num;
word_t words[1ll << 27];  // Up to 2^32 IP addresses

int get_bit(uint32_t ip_addr) {
    word_t bit = words[WORD_OFFSET(ip_addr)] & (1 << BIT_OFFSET(ip_addr));
    return bit != 0;
}

void set_bit(uint32_t ip_addr) {
    words[WORD_OFFSET(ip_addr)] |= (1 << BIT_OFFSET(ip_addr));
    if (get_bit(ip_addr))
        IP_addr_num++;
}

void signal_handler(int signo) {
    if (signo == SIGINT) {
        puts("\nIntrusion Detection Report: ");
        printf("%d SYN packets  detected from %d different IPs (syn attack)\n",
                syn_packets_count, IP_addr_num);
        printf("%d ARP responses (cache poisoning)\n", arp_packets_count);
        printf("%d URL Blacklist violations\n", violations_count);
        tpool_destroy(tm);
        exit(EXIT_SUCCESS);
    }
    assert(false);
}

void print_arp(const struct ether_arp *arp_ptr) {
    puts("Detect ARP responses");
    char mac_str[MAC_STR_LEN];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp_ptr->arp_sha[0], arp_ptr->arp_sha[1], arp_ptr->arp_sha[2],
             arp_ptr->arp_sha[3], arp_ptr->arp_sha[4], arp_ptr->arp_sha[5]);
    printf("Sender hardware address: %s\n", mac_str);
    printf("Sender IP address: %d.%d.%d.%d\n", arp_ptr->arp_spa[0],
           arp_ptr->arp_spa[1], arp_ptr->arp_spa[2], arp_ptr->arp_spa[3]);
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp_ptr->arp_tha[0], arp_ptr->arp_tha[1], arp_ptr->arp_tha[2],
             arp_ptr->arp_tha[3], arp_ptr->arp_tha[4], arp_ptr->arp_tha[5]);
    printf("Target hardware address: %s\n", mac_str);
    printf("Target IP address: %d.%d.%d.%d\n", arp_ptr->arp_tpa[0],
           arp_ptr->arp_tpa[1], arp_ptr->arp_tpa[2], arp_ptr->arp_tpa[3]);
}

static pthread_mutex_t mutex_syn_cnt = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mutex_arp_cnt = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mutex_vio_cnt = PTHREAD_MUTEX_INITIALIZER;

void analyse(void *args) {
    // !! Jast lock when adding statistics and adding list
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
                if (pthread_mutex_lock(&mutex_syn_cnt) != 0) {
                    perror("pthread_mutex_lock");
                    exit(EXIT_FAILURE);
                }
                set_bit(ip_ptr->ip_src.s_addr);
                syn_packets_count++;
                if (pthread_mutex_unlock(&mutex_syn_cnt) != 0) {
                    perror("pthread_mutex_unlock");
                    exit(EXIT_FAILURE);
                }
            }
            if (ntohs(tcp_ptr->dest) == 80) { // HTTP
                char *payload = (char *)(packet += tcp_ptr->th_off * 4);
                if (strstr(payload, "Host: www.google.co.uk") != NULL ||
                    strstr(payload, "Host: www.bbc.com") != NULL) {
                    if (pthread_mutex_lock(&mutex_vio_cnt) != 0) {
                        perror("pthread_mutex_lock");
                        exit(EXIT_FAILURE);
                    }
                    puts("=============================");
                    puts("Blacklisted URL violation detected");
                    printf("Source IP address: %s\n", inet_ntoa(ip_ptr->ip_src));
                    printf("Destination IP address: %s\n", inet_ntoa(ip_ptr->ip_dst));
                    puts("=============================");
                    violations_count++;
                    if (pthread_mutex_unlock(&mutex_vio_cnt) != 0) {
                        perror("pthread_mutex_unlock");
                        exit(EXIT_FAILURE);
                    }
                }
            }
        }
    } else if (ether_type == ETHERTYPE_ARP) { // ARP packet
        if (pthread_mutex_lock(&mutex_arp_cnt) != 0) {
            perror("pthread_mutex_lock");
            exit(EXIT_FAILURE);
        }
        arp_packets_count++;

        struct ether_arp *arp_ptr =
            (struct ether_arp *)(packet += sizeof(struct ether_header));
        print_arp(arp_ptr);

        if (pthread_mutex_unlock(&mutex_arp_cnt) != 0) {
            perror("pthread_mutex_unlock");
            exit(EXIT_FAILURE);
        }
    }
    free(((struct arguments *)args)->packet);
    free(args);
}

#define _GNU_SOURCE
#include "sniff.h"
#include "dispatch.h"

#include <netinet/if_ether.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

struct arguments {
    pcap_t *pcap_handle;
    int verbose;
};

void packet_handler(u_char *args, const struct pcap_pkthdr *header,
                    const u_char *packet) {
    struct arguments *arg = (struct arguments *)args;
    if (packet == NULL) {
        // pcap_next can return null if no packet is seen within a timeout
        if (arg->verbose) {
            printf("No packet received. %s\n", pcap_geterr(arg->pcap_handle));
        }
    } else {
        // If verbose is set to 1, dump raw packet to terminal
        if (arg->verbose) {
            dump(packet, header->len);
        }
        // Dispatch packet for processing
        dispatch(header, packet, arg->verbose);
    }
}

// Application main sniffing loop
void sniff(char *interface, int verbose) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the specified network interface for packet capture. pcap_open_live()
    // returns the handle to be used for the packet capturing session. check the
    // man page of pcap_open_live()
    pcap_t *pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Unable to open interface %s\n", errbuf);
        exit(EXIT_FAILURE);
    } else {
        printf("SUCCESS! Opened %s for capture\n", interface);
    }
    // Using pacp_loop() to more efficient capture packets
    struct arguments args = { pcap_handle, verbose };
    pcap_loop(pcap_handle, 0, packet_handler, (u_char*)&args);
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
    unsigned int i;
    static unsigned long pcount = 0;
    // Decode Packet Header
    struct ether_header *eth_header = (struct ether_header *)data;
    printf("\n\n === PACKET %ld HEADER ===", pcount);
    printf("\nSource MAC: ");
    for (i = 0; i < 6; ++i) {
        printf("%02x", eth_header->ether_shost[i]);
        if (i < 5) {
            printf(":");
        }
    }
    printf("\nDestination MAC: ");
    for (i = 0; i < 6; ++i) {
        printf("%02x", eth_header->ether_dhost[i]);
        if (i < 5) {
            printf(":");
        }
    }
    printf("\nType: %hu\n", eth_header->ether_type);
    printf(" === PACKET %ld DATA == \n", pcount);
    // Decode Packet Data (Skipping over the header)
    int data_bytes = length - ETH_HLEN;
    const unsigned char *payload = data + ETH_HLEN;
    const static int output_sz = 20;  // Output this many bytes at a time
    while (data_bytes > 0) {
        int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
        // Print data in raw hexadecimal form
        for (i = 0; i < output_sz; ++i) {
            if (i < output_bytes) {
                printf("%02x ", payload[i]);
            } else {
                printf("   ");  // Maintain padding for partial lines
            }
        }
        printf("| ");
        // Print data in ascii form
        for (i = 0; i < output_bytes; ++i) {
            char byte = payload[i];
            if (byte > 31 && byte < 127) {
                // Byte is in printable ascii range
                printf("%c", byte);
            } else {
                printf(".");
            }
        }
        printf("\n");
        payload += output_bytes;
        data_bytes -= output_bytes;
    }
    pcount++;
}

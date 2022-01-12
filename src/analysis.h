#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>
#include "dispatch.h"

struct arguments {
    const struct pcap_pkthdr *header;
    const unsigned char *packet;
    int verbose;
    tpool_t *tm;
};

void analyse(void *args);

#endif

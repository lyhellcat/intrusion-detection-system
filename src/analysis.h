#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>

void analyse(const struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose);

#endif

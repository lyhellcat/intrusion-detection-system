#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "sniff.h"
#include "dispatch.h"

// Command line options
#define OPTSTRING "vi:"
static struct option long_opts[] = {
  {"interface", optional_argument, NULL, 'i'},
  {"verbose",   optional_argument, NULL, 'v'}
};

struct arguments {
  char *interface;
  int verbose;
};

void print_usage(char *progname) {
  fprintf(stderr, "A Packet Sniffer/Intrusion Detection System tutorial\n");
  fprintf(stderr, "Usage: %s [OPTIONS]...\n\n", progname);
  fprintf(stderr, "\t-i [interface]\tSpecify network interface to sniff\n");
  fprintf(stderr, "\t-v\t\tEnable verbose mode. Useful for Debugging\n");
}

int main(int argc, char *argv[]) {
  // Parse command line arguments
  struct arguments args = {"eth0", 0}; // Default values
  int optc;
  while ((optc = getopt_long(argc, argv, OPTSTRING, long_opts, NULL)) != EOF) {
    switch (optc) {
      case 'v':
        args.verbose = 1;
        break;
      case 'i':
        args.interface = strdup(optarg);
        break;
      default:
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
  }
  // Print out settings
  printf("%s invoked. Settings:\n", argv[0]);
  printf("\tInterface: %s\n\tVerbose: %d\n", args.interface, args.verbose);
  // Invoke Intrusion Detection System
  sniff(args.interface, args.verbose);
  return 0;
}

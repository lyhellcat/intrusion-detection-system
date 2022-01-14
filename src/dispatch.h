#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>

typedef void (*thread_func_t)(void *arg);

// Work queue is a simple linked list
typedef struct tpool_work {
    thread_func_t func;
    void *arg;
    struct tpool_work *next;
} tpool_work_t;

typedef struct tpool {
    tpool_work_t *work_head;
    tpool_work_t *work_tail;
    pthread_mutex_t work_mutex;
    pthread_cond_t work_cond;     // There is work to be processed
    pthread_cond_t working_cond;  // No threads processing
    size_t working_cnt;  // How many threads are actively processing work
    size_t thread_cnt;   // How many threads are alive
    bool stop;
} tpool_t;

tpool_t *tpool_create(size_t num);
void tpool_destroy(tpool_t *tm);

bool tpool_add_work(tpool_t *tm, thread_func_t func, void *arg);
void tpool_wait(tpool_t *tm);  // blocks until all work has been completed

void dispatch(const struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose, tpool_t *tm);

#endif

#include "tpool.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>

static const size_t num_threads = 12;
static const size_t num_items = 1000;
static volatile int res = 0;

pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

void worker(void *arg) {
    pthread_mutex_lock(&mtx);
    res += *(int *)arg;
    pthread_mutex_unlock(&mtx);
}

int main(int argc, char **argv) {
    tpool_t *tm;
    int *vals;
    size_t i;

    tm = tpool_create(num_threads);
    vals = calloc(num_items, sizeof(*vals)); // vals in heap segment

    for (i = 0; i < 100000; i++) {
        // vals[i] = i;
        int *j = malloc(sizeof(int));
        memcpy(j, &i, sizeof(int));
        tpool_add_work(tm, worker, j);
    }

    tpool_wait(tm);

    printf("%d\n", res);

    tpool_destroy(tm);
    return 0;
}

#include "tpool.h"

tpool_work_t *tpool_work_create(thread_func_t func, void *arg) {
    tpool_work_t *work;
    if (func == NULL)
        return NULL;

    work = malloc(sizeof(*work));
    work->func = func;
    work->arg = arg;
    work->next = NULL;

    return work;
}

void tpool_work_destroy(tpool_work_t *work) {
    if (work == NULL)
        return;
    free(work);
}

tpool_work_t *tpool_work_get(tpool_t *tm) {
    tpool_work_t *work;
    if (tm == NULL)
        return NULL;
    work = tm->work_first;
    if (work == NULL)
        return NULL;
    if (work->next == NULL) {
        tm->work_first = NULL;
        tm->work_last = NULL;
    } else {
        tm->work_first = work->next;
    }
    return work;
}

// Worker function
void *tpool_worker(void *arg) {
    tpool_t *tm = arg;
    tpool_work_t *work;

    while (1) {
        pthread_mutex_lock(&(tm->work_mutex));
        // Check if there is any work available for processing
        while (tm->work_first == NULL && !tm->stop) {
            // unlock mutex
            // block thread, until work_cond signal
            // lock mutex
            pthread_cond_wait(&(tm->work_cond), &(tm->work_mutex));
        }
        if (tm->stop)
            break;

        work = tpool_work_get(tm);
        tm->working_cnt++;
        pthread_mutex_unlock(&(tm->work_mutex));

        if (work != NULL) {
            work->func(work->arg);
            tpool_work_destroy(work);
        }
        pthread_mutex_lock(&(tm->work_mutex));
        tm->working_cnt--;
        if (!tm->stop && tm->working_cnt == 0 && tm->work_first == NULL)
            pthread_cond_signal(&(tm->working_cond));
        pthread_mutex_unlock(&(tm->work_mutex));
    }
    tm->thread_cnt--; // Thread is stopping
    pthread_cond_signal(&(tm->working_cond));
    pthread_mutex_unlock(&(tm->work_mutex));
    return NULL;
}

tpool_t *tpool_create(size_t num) {
    tpool_t *tm;
    pthread_t thread;
    size_t i;

    if (num == 0) num = 2;

    tm = calloc(1, sizeof(*tm));
    tm->thread_cnt = num;

    pthread_mutex_init(&(tm->work_mutex), NULL);
    pthread_cond_init(&(tm->work_cond), NULL);
    pthread_cond_init(&(tm->working_cond), NULL);

    tm->work_first = NULL;
    tm->work_last = NULL;

    for (i = 0; i < num; i++) {
        pthread_create(&thread, NULL, tpool_worker, tm);
        pthread_detach(thread);
    }

    return tm;
}

void tpool_destroy(tpool_t *tm) {
    tpool_work_t *work;
    tpool_work_t *work2;

    if (tm == NULL) return;

    pthread_mutex_lock(&(tm->work_mutex));
    work = tm->work_first;
    while (work != NULL) {
        work2 = work->next;
        tpool_work_destroy(work);
        work = work2;
    }
    tm->stop = true;
    pthread_cond_broadcast(&(tm->work_cond));
    pthread_mutex_unlock(&(tm->work_mutex));

    tpool_wait(tm);

    pthread_mutex_destroy(&(tm->work_mutex));
    pthread_cond_destroy(&(tm->work_cond));
    pthread_cond_destroy(&(tm->working_cond));

    free(tm);
}

bool tpool_add_work(tpool_t *tm, thread_func_t func, void *arg) {
    tpool_work_t *work;

    if (tm == NULL) return false;

    work = tpool_work_create(func, arg);
    if (work == NULL) return false;

    pthread_mutex_lock(&(tm->work_mutex));
    if (tm->work_first == NULL) {
        tm->work_first = work;
        tm->work_last = tm->work_first;
    } else {
        tm->work_last->next = work;
        tm->work_last = work;
    }

    pthread_cond_broadcast(&(tm->work_cond));
    pthread_mutex_unlock(&(tm->work_mutex));

    return true;
}

void tpool_wait(tpool_t *tm) {
    if (tm == NULL) return;

    pthread_mutex_lock(&(tm->work_mutex));
    while (1) {
        if ((!tm->stop && tm->working_cnt != 0) ||
            (tm->stop && tm->thread_cnt != 0)) {
            pthread_cond_wait(&(tm->working_cond), &(tm->work_mutex));
        } else {
            break;
        }
    }
    pthread_mutex_unlock(&(tm->work_mutex));
}

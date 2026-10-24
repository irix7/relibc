extern int printf(const char *, ...);
typedef void *pthread_t;
extern int pthread_create(pthread_t *, const void *, void *(*)(void *), void *);
extern int pthread_join(pthread_t, void **);

static __thread int tls_value = 100;

static void *worker(void *arg) {
    tls_value = (int)(long)arg;
    printf("thread: tls=%d\n", tls_value);
    return (void *)(long)(tls_value + 1);
}

int main(void) {
    pthread_t t;
    void *ret = 0;
    printf("main: tls=%d\n", tls_value);
    int rc = pthread_create(&t, 0, worker, (void *)42L);
    if (rc != 0) {
        printf("pthread_create failed rc=%d\n", rc);
        return 2;
    }
    rc = pthread_join(t, &ret);
    if (rc != 0) {
        printf("pthread_join failed rc=%d\n", rc);
        return 3;
    }
    printf("joined: ret=%ld main_tls=%d\n", (long)ret, tls_value);
    return ret == (void *)43L && tls_value == 100 ? 0 : 1;
}

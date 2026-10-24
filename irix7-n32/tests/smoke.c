#include <setjmp.h>

extern int printf(const char *, ...);

static __thread int tls_var = 1234;
static jmp_buf env;
static int jumped;

int main(int argc, char **argv) {
    printf("hello: argc=%d tls=%d\n", argc, tls_var);
    tls_var = 5678;
    if (tls_var != 5678)
        return 1;

    int r = setjmp(env);
    if (r == 0) {
        jumped = 1;
        longjmp(env, 9);
    }
    printf("setjmp: r=%d jumped=%d tls=%d\n", r, jumped, tls_var);
    printf("formats: %d %u %ld %lld %zu %s %c %x %.2f %p\n",
           -7, 42u, 123456789L, -1234567890123LL,
           (unsigned long)sizeof(long), "str", 'A', 0xdeadbeefu,
           3.14159, (void *)argv);
    return (r == 9 && jumped == 1 && tls_var == 5678) ? 0 : 2;
}

#include <stdio.h>
typedef unsigned long long jmp_buf[20];
extern int setjmp(jmp_buf);
extern void longjmp(jmp_buf, int);
static jmp_buf env;
static int depth;
static void jump(void) { depth++; longjmp(env, 7); }
int main(void) {
    int r = setjmp(env);
    if (r == 0) { jump(); return 1; }
    printf("setjmp/longjmp n32: r=%d depth=%d\n", r, depth);
    return r == 7 && depth == 1 ? 0 : 1;
}

extern int printf(const char *, ...);
int main(int argc, char **argv) {
    printf("relibc n32 hello: argc=%d argv0=%s\n", argc, argv[0]);
    return 0;
}

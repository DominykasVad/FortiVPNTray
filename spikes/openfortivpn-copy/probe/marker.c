// A library that does nothing but record that it was loaded. Stands in for hostile code.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) static void loaded(void) {
    const char *path = getenv("SPIKE_MARKER");
    if (!path) return;
    FILE *f = fopen(path, "w");
    if (f) { fprintf(f, "loaded into pid %d, uid %d, euid %d\n", getpid(), getuid(), geteuid()); fclose(f); }
}

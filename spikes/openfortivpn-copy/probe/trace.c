// Interposes fopen/open/stat and reports every path that mentions Homebrew or ssl.
// Loaded with DYLD_INSERT_LIBRARIES into probe; shows which files the copied OpenSSL reads.
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>
#define INTERPOSE(new, old) __attribute__((used)) static struct { const void *n; const void *o; } _i_##old __attribute__((section("__DATA,__interpose"))) = { (const void *)new, (const void *)old }
static void note(const char *call, const char *path) { if (path && (strstr(path, "homebrew") || strstr(path, "ssl"))) fprintf(stderr, "TRACE %s %s\n", call, path); }
static FILE *my_fopen(const char *path, const char *mode) { note("fopen", path); return fopen(path, mode); }
static int my_open(const char *path, int flags, ...) { va_list a; va_start(a, flags); int mode = va_arg(a, int); va_end(a); note("open", path); return open(path, flags, mode); }
static int my_stat(const char *path, struct stat *s) { note("stat", path); return stat(path, s); }
INTERPOSE(my_fopen, fopen); INTERPOSE(my_open, open); INTERPOSE(my_stat, stat);

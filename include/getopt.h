// Minimal getopt / getopt_long shim — vendored so the project builds on
// MSVC, which does not ship <getopt.h>. The semantics match a GNU subset
// sufficient for src/main.c (short opts + --long opts with required
// arguments; supports "--opt=value" and "--opt value" forms).

#ifndef HGS_GETOPT_H
#define HGS_GETOPT_H

#ifdef __cplusplus
extern "C" {
#endif

extern char *optarg;
extern int   optind;
extern int   opterr;
extern int   optopt;

struct option {
    const char *name;
    int         has_arg;
    int        *flag;
    int         val;
};

#define no_argument        0
#define required_argument  1
#define optional_argument  2

int getopt(int argc, char * const argv[], const char *optstring);
int getopt_long(int argc, char * const argv[], const char *optstring,
                const struct option *longopts, int *longindex);

#ifdef __cplusplus
}
#endif

#endif /* HGS_GETOPT_H */

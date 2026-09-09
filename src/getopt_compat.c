// Minimal getopt / getopt_long implementation — public-domain style.
// Sufficient for HGS-Analyzer's CLI in src/main.c.
//
// Supports:
//   - short options with optional ':' for required args  ("t:m:")
//   - long options with required_argument / no_argument
//   - "--opt=value" and "--opt value" forms
//   - "--" sentinel ends option parsing
//   - flag-style long options that write to *option.flag

#include "getopt.h"
#include <string.h>
#include <stdio.h>

char *optarg = NULL;
int   optind = 1;
int   opterr = 1;
int   optopt = '?';

static int s_nextchar = 0;
static char *s_arg = NULL;

int getopt(int argc, char * const argv[], const char *optstring)
{
    char c;
    const char *p;

    if (s_nextchar == 0 || s_arg == NULL) {
        if (optind >= argc) return -1;
        s_arg = argv[optind];
        if (s_arg[0] != '-' || s_arg[1] == '\0') return -1;
        if (s_arg[1] == '-' && s_arg[2] == '\0') { optind++; return -1; }
        s_nextchar = 1;
    }

    c = s_arg[s_nextchar++];
    p = strchr(optstring, c);

    if (p == NULL || c == ':') {
        if (opterr && optstring[0] != ':') {
            fprintf(stderr, "unknown option: -%c\n", c);
        }
        optopt = c;
        if (s_arg[s_nextchar] == '\0') { optind++; s_nextchar = 0; }
        return '?';
    }

    if (p[1] == ':') {
        if (s_arg[s_nextchar] != '\0') {
            optarg = &s_arg[s_nextchar];
            optind++;
            s_nextchar = 0;
        } else if (++optind < argc) {
            optarg = argv[optind];
            optind++;
            s_nextchar = 0;
        } else {
            if (opterr && optstring[0] != ':') {
                fprintf(stderr, "option -%c requires an argument\n", c);
            }
            optopt = c;
            s_nextchar = 0;
            return (optstring[0] == ':') ? ':' : '?';
        }
    } else {
        if (s_arg[s_nextchar] == '\0') { optind++; s_nextchar = 0; }
    }

    return c;
}

int getopt_long(int argc, char * const argv[], const char *optstring,
                const struct option *longopts, int *longindex)
{
    char *arg;
    const char *name;
    const char *eq;
    size_t name_len;
    int i;

    if (optind >= argc) return -1;
    arg = argv[optind];

    if (arg[0] != '-' || arg[1] == '\0') return -1;

    /* Single-dash short option(s) → delegate to getopt(). */
    if (arg[1] != '-') return getopt(argc, argv, optstring);

    /* "--" sentinel — end of options. */
    if (arg[2] == '\0') { optind++; return -1; }

    /* "--name" or "--name=value". */
    name = arg + 2;
    eq = strchr(name, '=');
    name_len = eq ? (size_t)(eq - name) : strlen(name);

    for (i = 0; longopts[i].name != NULL; i++) {
        if (strlen(longopts[i].name) == name_len
            && strncmp(longopts[i].name, name, name_len) == 0) {

            if (longindex) *longindex = i;
            optind++;

            if (longopts[i].has_arg == required_argument) {
                if (eq != NULL) {
                    optarg = (char *)(eq + 1);
                } else if (optind < argc) {
                    optarg = argv[optind++];
                } else {
                    if (opterr) {
                        fprintf(stderr, "option --%s requires an argument\n",
                                longopts[i].name);
                    }
                    optopt = longopts[i].val;
                    return (optstring[0] == ':') ? ':' : '?';
                }
            } else if (longopts[i].has_arg == optional_argument) {
                optarg = eq ? (char *)(eq + 1) : NULL;
            } else {
                optarg = NULL;
                if (eq != NULL && opterr) {
                    fprintf(stderr, "option --%s takes no argument\n",
                            longopts[i].name);
                }
            }

            if (longopts[i].flag != NULL) {
                *longopts[i].flag = longopts[i].val;
                return 0;
            }
            return longopts[i].val;
        }
    }

    if (opterr) {
        fprintf(stderr, "unknown option: --%.*s\n", (int)name_len, name);
    }
    optopt = 0;
    optind++;
    return '?';
}

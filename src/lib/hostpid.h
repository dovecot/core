#ifndef HOSTPID_H
#define HOSTPID_H

extern const char *my_hostname;
extern const char *my_pid;

/* Initializes my_hostname and my_pid. */
void hostpid_init(void);

/* Returns the current host+domain, or if it fails fallback to returning
   hostname. */
const char *my_hostdomain(void);

#endif


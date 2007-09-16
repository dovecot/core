#ifndef HOSTPID_H
#define HOSTPID_H

extern const char *my_hostname;
extern const char *my_pid;

/* Initializes my_hostname and my_pid. Done only once, so it's safe and
   fast to call this function multiple times. */
void hostpid_init(void);

#endif


#ifndef HOSTPID_H
#define HOSTPID_H

/* These environments override the hostname/hostdomain if they're set.
   Master process normally sets these to child processes. */
#define MY_HOSTNAME_ENV "DOVECOT_HOSTNAME"
#define MY_HOSTDOMAIN_ENV "DOVECOT_HOSTDOMAIN"

extern const char *my_hostname;
extern const char *my_pid;

/* Initializes my_hostname and my_pid. */
void hostpid_init(void);
void hostpid_deinit(void);

/* Returns the current host+domain, or if it fails fallback to returning
   hostname. */
const char *my_hostdomain(void);

#endif


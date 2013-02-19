/* Copyright (c) 2002-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hostpid.h"

#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>

#define HOSTNAME_DISALLOWED_CHARS "/\r\n\t"

const char *my_hostname = NULL;
const char *my_pid = NULL;

static char *my_hostname_dup = NULL;
static char *my_domain = NULL;

void hostpid_init(void)
{
	static char pid[MAX_INT_STRLEN];
	char hostname[256];
	const char *value;

	/* allow calling hostpid_init() multiple times to reset hostname */
	i_free_and_null(my_hostname_dup);
	i_free_and_null(my_domain);

	value = getenv(MY_HOSTNAME_ENV);
	if (value == NULL) {
		if (gethostname(hostname, sizeof(hostname)-1) < 0)
			i_fatal("gethostname() failed: %m");
		hostname[sizeof(hostname)-1] = '\0';
		value = hostname;
	}

	if (value[0] == '\0' ||
	    strcspn(value, HOSTNAME_DISALLOWED_CHARS) != strlen(value))
		i_fatal("Invalid system hostname: '%s'", value);
	my_hostname_dup = i_strdup(value);
	my_hostname = my_hostname_dup;

	i_snprintf(pid, sizeof(pid), "%lld", (long long)getpid());
	my_pid = pid;
}

void hostpid_deinit(void)
{
	i_free(my_hostname_dup);
	i_free(my_domain);
}

const char *my_hostdomain(void)
{
	struct hostent *hent;
	const char *name;

	if (my_domain == NULL) {
		name = getenv(MY_HOSTDOMAIN_ENV);
		if (name == NULL) {
			hent = gethostbyname(my_hostname);
			name = hent != NULL ? hent->h_name : NULL;
			if (name == NULL) {
				/* failed, use just the hostname */
				name = my_hostname;
			}
		}
		my_domain = i_strdup(name);
	}
	return my_domain;
}

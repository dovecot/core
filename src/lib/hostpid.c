/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hostpid.h"

#include <unistd.h>
#include <netdb.h>

const char *my_hostname = NULL;
const char *my_pid = NULL;

static char *my_domain = NULL;

void hostpid_init(void)
{
	static char hostname[256], pid[MAX_INT_STRLEN];

	if (gethostname(hostname, sizeof(hostname)-1) == -1)
		i_strocpy(hostname, "unknown", sizeof(hostname));
	hostname[sizeof(hostname)-1] = '\0';
	my_hostname = hostname;

	if (strchr(hostname, '/') != NULL)
		i_fatal("Invalid system hostname: %s", hostname);

	/* allow calling hostpid_init() multiple times to reset hostname */
	i_free_and_null(my_domain);

	i_strocpy(pid, dec2str(getpid()), sizeof(pid));
	my_pid = pid;
}

const char *my_hostdomain(void)
{
	struct hostent *hent;
	const char *name;

	if (my_domain == NULL) {
		hent = gethostbyname(my_hostname);
		name = hent != NULL ? hent->h_name : NULL;
		if (name == NULL) {
			/* failed, use just the hostname */
			name = my_hostname;
		}
		my_domain = i_strdup(name);
	}
	return my_domain;
}

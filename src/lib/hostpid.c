/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hostpid.h"

#include <unistd.h>

const char *my_hostname = NULL;
const char *my_pid = NULL;

void hostpid_init(void)
{
	static char hostname[256], pid[MAX_INT_STRLEN];

	if (my_hostname == NULL) {
		if (gethostname(hostname, sizeof(hostname)-1) == -1)
			i_strocpy(hostname, "unknown", sizeof(hostname));
		hostname[sizeof(hostname)-1] = '\0';

		my_hostname = hostname;
	}

	if (my_pid == NULL) {
		i_strocpy(pid, dec2str(getpid()), sizeof(pid));
		my_pid = pid;
	}
}

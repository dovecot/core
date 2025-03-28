/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hostpid.h"

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
        const char *name;
        struct addrinfo hints, *res;

        if (my_domain != NULL) {
                return my_domain;
        }

        name = getenv(MY_HOSTDOMAIN_ENV);
        if (name != NULL) {
                my_domain = i_strdup(name);
                return my_domain;
        }

        i_zero(&hints);
        hints.ai_family = AF_UNSPEC;            // IPV4 or IPV6
        hints.ai_socktype = SOCK_STREAM;        // TCP
        hints.ai_flags = AI_CANONNAME;

        if (getaddrinfo(my_hostname, NULL, &hints, &res) == 0) {
                my_domain = i_strdup(res->ai_canonname);
                freeaddrinfo(res);
                return my_domain;
        }

        /* failed, use just the hostname */
        my_domain = i_strdup(my_hostname);
        return my_domain;
}

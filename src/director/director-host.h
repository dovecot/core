#ifndef DIRECTOR_HOST_H
#define DIRECTOR_HOST_H

#include "network.h"

struct director;

struct director_host {
	struct ip_addr ip;
	unsigned int port;

	/* name contains "ip:port" */
	char *name;

	/* each command between directors contains an increasing sequence.
	   if director A gets conflicting information about director B, it can
	   trust the one that has the highest sequence. */
	unsigned int last_seq;

	/* Last time host was detected to be down/broken */
	time_t last_failed;

	/* we are this director */
	unsigned int self:1;
};

struct director_host *
director_host_add(struct director *dir, const struct ip_addr *ip,
		  unsigned int port);
void director_host_free(struct director_host *host);

struct director_host *
director_host_get(struct director *dir, const struct ip_addr *ip,
		  unsigned int port);
struct director_host *
director_host_lookup(struct director *dir, const struct ip_addr *ip,
		     unsigned int port);
struct director_host *
director_host_lookup_ip(struct director *dir, const struct ip_addr *ip);

/* Returns 0 if b1 equals b2.
   -1 if b1 is closer to our left side than b2 or
   -1 if b2 is closer to our right side than b1
   1 vice versa */
int director_host_cmp_to_self(const struct director_host *b1,
			      const struct director_host *b2,
			      const struct director_host *self);

/* Parse hosts list (e.g. "host1:port host2 host3:port") and them as
   directors */
void director_host_add_from_string(struct director *dir, const char *hosts);

#endif

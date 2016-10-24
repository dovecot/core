#ifndef DIRECTOR_HOST_H
#define DIRECTOR_HOST_H

#include "net.h"

struct director;

struct director_host {
	struct director *dir;
	int refcount;

	struct ip_addr ip;
	in_port_t port;

	/* name contains "ip:port" */
	char *name;
	/* change commands each have originating host and originating sequence.
	   we'll keep track of the highest sequence we've seen from the host.
	   if we find a lower sequence, we've already handled the command and
	   it can be ignored (or: it must be ignored to avoid potential command
	   loops) */
	unsigned int last_seq;
	/* use these to avoid infinitely sending SYNCs for directors that
	   aren't connected in the ring. */
	unsigned int last_sync_seq, last_sync_seq_counter, last_sync_timestamp;
	/* whenever we receive a SYNC with stale hosts_hash, set this. if it's
	   already set and equals the current hosts_hash, re-send our hosts to
	   everybody in case they somehow got out of sync. */
	unsigned int desynced_hosts_hash;
	/* Last time host was detected to be down */
	time_t last_network_failure;
	time_t last_protocol_failure;

	/* When we finish getting a right connection, send a SYNC with these
	   parameters (if delayed_sync_seq != 0) */
	uint32_t delayed_sync_seq;
	unsigned int delayed_sync_minor_version;
	unsigned int delayed_sync_timestamp;
	unsigned int delayed_sync_hosts_hash;

	/* we are this director */
	bool self:1;
	bool removed:1;
};

struct director_host *
director_host_add(struct director *dir, const struct ip_addr *ip,
		  in_port_t port);
void director_host_free(struct director_host **host);

void director_host_ref(struct director_host *host);
void director_host_unref(struct director_host *host);

void director_host_restarted(struct director_host *host);

struct director_host *
director_host_get(struct director *dir, const struct ip_addr *ip,
		  in_port_t port);
struct director_host *
director_host_lookup(struct director *dir, const struct ip_addr *ip,
		     in_port_t port);
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

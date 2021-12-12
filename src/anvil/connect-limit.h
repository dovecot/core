#ifndef CONNECT_LIMIT_H
#define CONNECT_LIMIT_H

#include "net.h"
#include "guid.h"

struct connect_limit_key {
	/* User's primary username */
	const char *username;
	/* Service name */
	const char *service;
	/* IP address. If family==0, there is no IP. */
	struct ip_addr ip;
};

struct connect_limit *connect_limit_init(void);
void connect_limit_deinit(struct connect_limit **limit);

unsigned int
connect_limit_lookup(struct connect_limit *limit,
		     const struct connect_limit_key *key);
void connect_limit_connect(struct connect_limit *limit, pid_t pid,
			   const struct connect_limit_key *key,
			   const guid_128_t conn_guid);
void connect_limit_disconnect(struct connect_limit *limit, pid_t pid,
			      const struct connect_limit_key *key,
			      const guid_128_t conn_guid);
void connect_limit_disconnect_pid(struct connect_limit *limit, pid_t pid);
void connect_limit_dump(struct connect_limit *limit, struct ostream *output);

#endif

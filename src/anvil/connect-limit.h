#ifndef CONNECT_LIMIT_H
#define CONNECT_LIMIT_H

#include "net.h"
#include "guid.h"

enum kick_type {
	/* This process doesn't support kicking users */
	KICK_TYPE_NONE,
	/* User kicking should be done by sending TERM signal */
	KICK_TYPE_SIGNAL,
	/* User kicking should be done by sending KICK-USER command to the
	   process's admin socket or the existing anvil connection. */
	KICK_TYPE_ADMIN_SOCKET,
};

struct connect_limit_key {
	/* User's primary username */
	const char *username;
	/* Service name */
	const char *service;
	/* IP address. If family==0, there is no IP. */
	struct ip_addr ip;
};

struct connect_limit_iter_result {
	enum kick_type kick_type;
	pid_t pid;
	const char *service;
	const char *username;
	guid_128_t conn_guid;
};

struct connect_limit *connect_limit_init(void);
void connect_limit_deinit(struct connect_limit **limit);

unsigned int
connect_limit_lookup(struct connect_limit *limit,
		     const struct connect_limit_key *key);
void connect_limit_connect(struct connect_limit *limit, pid_t pid,
			   const struct connect_limit_key *key,
			   const guid_128_t conn_guid,
			   enum kick_type kick_type,
			   const char *const *alt_usernames);
void connect_limit_disconnect(struct connect_limit *limit, pid_t pid,
			      const struct connect_limit_key *key,
			      const guid_128_t conn_guid);
void connect_limit_disconnect_pid(struct connect_limit *limit, pid_t pid);
void connect_limit_dump(struct connect_limit *limit, struct ostream *output);

/* Iterate through sessions of the username. The connect-limit shouldn't be
   modified while the iterator exists. The results are sorted by pid. */
struct connect_limit_iter *
connect_limit_iter_begin(struct connect_limit *limit, const char *username);
struct connect_limit_iter *
connect_limit_iter_begin_alt_username(struct connect_limit *limit,
				      const char *alt_username_field,
				      const char *alt_username,
				      const struct ip_addr *except_ip);
bool connect_limit_iter_next(struct connect_limit_iter *iter,
			     struct connect_limit_iter_result *result_r);
void connect_limit_iter_deinit(struct connect_limit_iter **iter);

#endif

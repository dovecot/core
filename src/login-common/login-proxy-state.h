#ifndef LOGIN_PROXY_STATE_H
#define LOGIN_PROXY_STATE_H

#include <sys/time.h>

struct login_proxy_record {
	struct ip_addr ip;
	in_port_t port;

	/* These are used to spread client-visible disconnects over longer
	   periods of time to avoid reconnect spikes when a server dies.

	   If num_disconnects_since_ts=0 when server disconnects us, it's
	   increased and disconnect_timestamp is updated. Afterwards it's
	   increased for each new disconnection. num_disconnects_since_ts gets
	   reset back to zero whenever a) last_success gets updated or b)
	   num_delayed_client_disconnects drops to 0. */
	struct timeval disconnect_timestamp;
	unsigned int num_disconnects_since_ts;
	unsigned int num_delayed_client_disconnects;

	/* these are tracking connect()s, not necessarily logins: */
	unsigned int num_waiting_connections;
	/* number of connections we're proxying now (post-login) */
	unsigned int num_proxying_connections;
	struct timeval last_failure;
	struct timeval last_success;
};

struct login_proxy_state *login_proxy_state_init(const char *notify_path);
void login_proxy_state_deinit(struct login_proxy_state **state);

struct login_proxy_record *
login_proxy_state_get(struct login_proxy_state *state,
		      const struct ip_addr *ip, in_port_t port);

void login_proxy_state_notify(struct login_proxy_state *state,
			      const char *user);

#endif

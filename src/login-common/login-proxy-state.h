#ifndef LOGIN_PROXY_STATE_H
#define LOGIN_PROXY_STATE_H

#include <sys/time.h>

struct login_proxy_record {
	struct timeval last_failure;
	struct timeval last_success;
	unsigned int num_waiting_connections;
};

struct login_proxy_state *login_proxy_state_init(void);
void login_proxy_state_deinit(struct login_proxy_state **state);

struct login_proxy_record *
login_proxy_state_get(struct login_proxy_state *state,
		      const struct ip_addr *ip);

#endif

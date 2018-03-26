#ifndef CLIENT_RESET_H
#define CLIENT_RESET_H

struct client;

int client_stats_reset(struct client *client, const char *const *args,
			const char **error_r);

#endif

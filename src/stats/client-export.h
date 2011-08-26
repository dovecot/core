#ifndef CLIENT_EXPORT_H
#define CLIENT_EXPORT_H

struct client;

int client_export(struct client *client, const char *const *args,
		  const char **error_r);

#endif

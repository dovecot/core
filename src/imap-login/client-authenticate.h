#ifndef CLIENT_AUTHENTICATE_H
#define CLIENT_AUTHENTICATE_H

struct imap_arg;

void client_authenticate_get_capabilities(struct client *client, string_t *str);

bool imap_client_auth_handle_reply(struct client *client,
				   const struct client_auth_reply *reply);

int cmd_login(struct imap_client *client, const struct imap_arg *args);
int cmd_authenticate(struct imap_client *client, const struct imap_arg *args);

#endif

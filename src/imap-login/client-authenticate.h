#ifndef CLIENT_AUTHENTICATE_H
#define CLIENT_AUTHENTICATE_H

struct imap_arg;

void client_authenticate_get_capabilities(struct client *client, string_t *str);

void imap_client_auth_result(struct client *client,
			     enum client_auth_result result,
			     const struct client_auth_reply *reply,
			     const char *text);

int cmd_login(struct imap_client *client, const struct imap_arg *args);
int cmd_authenticate(struct imap_client *imap_client, bool *parsed_r);

#endif

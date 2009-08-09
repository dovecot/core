#ifndef CLIENT_AUTHENTICATE_H
#define CLIENT_AUTHENTICATE_H

struct imap_arg;

const char *client_authenticate_get_capabilities(struct imap_client *client);

int cmd_login(struct imap_client *client, const struct imap_arg *args);
int cmd_authenticate(struct imap_client *client, const struct imap_arg *args);

#endif

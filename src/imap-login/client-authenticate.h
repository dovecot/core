#ifndef __CLIENT_AUTHENTICATE_H
#define __CLIENT_AUTHENTICATE_H

const char *client_authenticate_get_capabilities(bool secured);

int cmd_login(struct imap_client *client, const struct imap_arg *args);
int cmd_authenticate(struct imap_client *client, const struct imap_arg *args);

#endif

#ifndef __CLIENT_AUTHENTICATE_H
#define __CLIENT_AUTHENTICATE_H

const char *client_authenticate_get_capabilities(void);

int cmd_login(struct client *client, struct imap_arg *args);
int cmd_authenticate(struct client *client, struct imap_arg *args);

#endif

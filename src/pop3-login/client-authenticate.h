#ifndef __CLIENT_AUTHENTICATE_H
#define __CLIENT_AUTHENTICATE_H

int cmd_user(struct pop3_client *client, const char *args);
int cmd_pass(struct pop3_client *client, const char *args);
int cmd_auth(struct pop3_client *client, const char *args);

#endif

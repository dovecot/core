#ifndef CLIENT_AUTHENTICATE_H
#define CLIENT_AUTHENTICATE_H

bool cmd_capa(struct pop3_client *client, const char *args);
bool cmd_user(struct pop3_client *client, const char *args);
bool cmd_pass(struct pop3_client *client, const char *args);
bool cmd_auth(struct pop3_client *client, const char *args);
bool cmd_apop(struct pop3_client *client, const char *args);

#endif

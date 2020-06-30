#ifndef CLIENT_AUTHENTICATE_H
#define CLIENT_AUTHENTICATE_H

void pop3_client_auth_result(struct client *client,
			     enum client_auth_result result,
			     const struct client_auth_reply *reply,
			     const char *text);

bool cmd_capa(struct pop3_client *client, const char *args);
bool cmd_user(struct pop3_client *client, const char *args);
bool cmd_pass(struct pop3_client *client, const char *args);
int cmd_auth(struct pop3_client *client, bool *parsed_r);
bool cmd_apop(struct pop3_client *client, const char *args);

#endif
